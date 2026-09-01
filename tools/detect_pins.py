#!/usr/bin/env python3
"""Auto-detect which FX2 channels carry the SIM signals (CLK / I-O / RST / VCC).

Reads an existing sigrok .sr capture, or records a short live one, then
classifies every channel and prints the wiring plus a ready-to-paste
start.sh command line.

Usage:
  python3 tools/detect_pins.py capture.sr [--max-samples=N]
  python3 tools/detect_pins.py --live [--samplerate=12M] [--seconds=2]

Requires: python3 + numpy.  The probe window should cover a phone power-
on or card reset so VCC/RST/DATA show their activation ordering; static
channels are reported honestly as ambiguous instead of guessed.

Clock Stop Mode (phones gate or stop CLK between transactions) is handled:
CLK is detected from its *local* period and burst density, not the average
edge rate, so a gated clock is still found, and a stopped-high clock is not
mistaken for a supply line.
"""

import argparse
import configparser
import re
import subprocess
import sys
import tempfile
import time
import zipfile

import numpy as np


# Evidence-capture tunables ----------------------------------------------
KEEP_TRANS = 512          # transition timestamps kept per channel
MAX_ONSETS = 64           # burst onsets kept per channel
ONSET_SILENCE_SEC = 0.2   # quiet time that marks a DATA burst onset
IDLE_SILENCE_SEC = 0.05   # span with NO transitions on any pin = idle
                          # (Clock Stop Mode); excluded from high% so a
                          # gated clock reads ~50% duty during bursts.
RESET_WIN_BEFORE = 0.150  # RST pulse lead vs burst onset (seconds)
RESET_WIN_AFTER = 0.020


# ---------------------------------------------------------------- input --

def parse_rate(s):
    '''Accept both .sr metadata spellings ("25 MHz") and CLI shorthand
    ("12M", "400kHz", bare "1000").  Case-insensitive; 'm' means mega.'''
    m = re.fullmatch(r'\s*([\d.]+)\s*([GMk])?\s*(?:Hz)?\s*', s,
                     re.IGNORECASE)
    if not m:
        raise ValueError('bad samplerate string: %r' % s)
    unit = m.group(2).lower() if m.group(2) else ''
    mult = {'g': 1e9, 'm': 1e6, 'k': 1e3, '': 1}[unit]
    return int(float(m.group(1)) * mult)


def load_sr(path, max_samples=None):
    """Return (samples uint8 array, samplerate, n_channels).

    Members are streamed into a growing bytearray so multi-GB captures
    never double in memory; max_samples bounds the result."""
    zf = zipfile.ZipFile(path)
    meta = configparser.ConfigParser()
    meta.read_string(zf.read('metadata').decode())
    sec = meta['device 1']
    nch = int(sec['total probes'])
    unitsize = int(sec.get('unitsize', 1))
    if unitsize != 1:
        # 16-bit profiles (9/16-channel sticks) are exactly what this
        # tool exists to avoid -- generic 8-channel dongles stream
        # unitsize=1.
        raise ValueError('unsupported unitsize %d (need an 8-channel '
                         'unitsize=1 capture)' % unitsize)
    samplerate = parse_rate(sec['samplerate'])
    names = sorted((n for n in zf.namelist()
                    if re.fullmatch(r'logic-\d+-\d+', n)),
                   key=lambda n: int(n.split('-')[-1]))
    buf = bytearray()
    limit = None if max_samples is None else max_samples * unitsize
    for n in names:
        buf.extend(zf.read(n))
        if limit is not None and len(buf) >= limit:
            break
    if limit is not None and len(buf) > limit:
        del buf[limit:]
    usable = len(buf) // unitsize * unitsize
    arr = np.frombuffer(bytes(buf[:usable]), dtype=np.uint8)
    return arr, samplerate, nch


# ------------------------------------------------------------ features ----

class ChannelAcc:
    """Incremental per-channel statistics over arbitrary chunk sizes.

    Tracks: edge count, high ratio, first rise, last transition, and a
    histogram of inter-transition gaps capped at GAP_CAP samples.  The
    capped-histogram median is what makes clock detection immune to
    gating: gating adds a FEW enormous gaps which land in the overflow
    bucket and never move the median away from half a clock period."""
    GAP_CAP = 4096

    def __init__(self, samplerate):
        self.sr = samplerate
        self.edges = 0
        self.rises = 0
        self.high = 0
        self.total = 0
        self.first_t = None         # first transition (any direction)
        self.first_rise = None      # in samples
        self.last_t = None          # in samples
        self._last = None
        self.fr_idx = None          # global index of first rise
        self.post_n = 0             # samples at/after first rise
        self.post_high = 0          # high samples at/after first rise
        self.hist = np.zeros(self.GAP_CAP + 1, dtype=np.int64)
        self.trans_kept = []        # first transition indices (samples)
        self.onsets = []            # burst onsets (samples)
        self._onset_gap = int(ONSET_SILENCE_SEC * samplerate)

    def feed(self, x, base):
        '''x: uint8 0/1 slice; base: global index of x[0].'''
        n = len(x)
        if n == 0:
            return
        if self._last is None:
            self._last = int(x[0])
        y = np.empty(n + 1, dtype=np.uint8)
        y[0] = self._last
        y[1:] = x
        self._last = int(y[-1])
        self.total += n
        self.high += int(x.sum())
        tt = np.nonzero(y[1:] != y[:-1])[0]          # offsets into y[1:]
        if len(tt) == 0:
            # Even without transitions the post-rise window may cover us.
            if self.fr_idx is not None:
                self.post_n += n
                self.post_high += int(x.sum())
            return
        g = base + tt                                # global positions
        lv = y[1:][tt]                               # new levels
        if len(self.trans_kept) < KEEP_TRANS:
            need = KEEP_TRANS - len(self.trans_kept)
            self.trans_kept.extend(int(v) for v in g[:need])
        if len(self.onsets) < MAX_ONSETS:
            # First transition of the stream counts as an onset too:
            # a capture that starts right at a burst still anchors.
            if self.last_t is None or \
                    (g[0] - self.last_t) >= self._onset_gap:
                self.onsets.append(int(g[0]))
            if len(g) > 1:
                gg = np.diff(g)
                for p in np.nonzero(gg >= self._onset_gap)[0]:
                    if len(self.onsets) < MAX_ONSETS:
                        self.onsets.append(int(g[p + 1]))
        if self.first_t is None:
            self.first_t = int(g[0])
        rise_pos = np.nonzero(lv == 1)[0]
        self.rises += len(rise_pos)
        if self.fr_idx is None and len(rise_pos):
            self.fr_idx = int(g[rise_pos[0]])
            self.first_rise = self.fr_idx
        # Gap series: chained across chunks AND within a chunk.
        chain = g if self.last_t is None else \
            np.concatenate((np.array([self.last_t], dtype=g.dtype), g))
        if len(chain) >= 2:
            gaps = np.minimum(np.diff(chain), self.GAP_CAP)
            self.hist += np.bincount(gaps,
                                     minlength=self.GAP_CAP + 1)
        self.last_t = int(g[-1])
        self.edges += len(g)
        # Post-first-rise level accounting (split at the rise sample).
        if self.fr_idx is not None:
            k = min(max(self.fr_idx - base, 0), n)
            self.post_n += (n - k)
            self.post_high += int(x[k:].sum())

    def stats(self):
        tot = int(self.hist.sum())
        med_gap = None
        short_edges = None
        long_edges = None
        if tot:
            cum = np.cumsum(self.hist)
            med_gap = int(np.searchsorted(cum, (tot + 1) // 2))
            # Burst density: count of inter-transition gaps that sit at (or
            # below) twice the median, i.e. inside a real clock burst.  Gating
            # / Clock Stop Mode only adds a FEW enormous gaps (they land in the
            # GAP_CAP overflow bucket), so the short/long split cleanly
            # separates a gated clock's bursts from its idle stretches.
            hi = min(med_gap * 2, self.GAP_CAP)
            short_edges = int(cum[hi])
            long_edges = tot - short_edges
        return {
            'edges': self.edges,
            'rate': self.edges * self.sr / max(self.total, 1),
            'high': self.high / max(self.total, 1),
            'median_gap': med_gap,
            'short_edges': short_edges,
            'long_edges': long_edges,
            'rises': self.rises,
            'falls': self.edges - self.rises,
            'post_duty': (self.post_high / self.post_n
                          if self.post_n else None),
            'first_t': (self.first_t / self.sr
                        if self.first_t is not None else None),
            'first_rise': (self.first_rise / self.sr
                           if self.first_rise is not None else None),
            'last_act': (self.last_t / self.sr
                         if self.last_t is not None else None),
            'trans': list(self.trans_kept),
            'onsets': list(self.onsets),
        }


# ----------------------------------------------------------- classifier ---

def classify(stats_list, samplerate, duration):
    '''Return dict ch -> (verdict, confidence), plus notes list.'''
    verdicts = {}
    notes = []
    rates = [s['rate'] for s in stats_list]

    # CLK: the channel whose *local* toggling period implies a running clock
    # (>= 1 MHz) and which actually clocks for a real stretch (enough
    # short-period edges to be a burst, not one isolated transition).  Gating /
    # Clock Stop Mode inserts long idle gaps that only lower the *average* edge
    # rate, so we score on the local period and burst density (median gap ->
    # local_freq, plus short_edges from the gap histogram) rather than the
    # average rate.  A gated CLK is still detected this way.
    def _local_freq(s):
        med = s['median_gap']
        if not med:
            return 0.0
        return samplerate / (2 * med)

    clk = None
    clock_chs = set()
    for c, s in enumerate(stats_list):
        if _local_freq(s) >= 1e6 and (s['short_edges'] or 0) >= 32:
            clock_chs.add(c)
    if clock_chs:
        # The genuine CLK is the one with the most burst edges; any other
        # clock-frequency channel is an alias/glitch and must not be claimed
        # as VCC/RST below.
        clk = max(clock_chs,
                  key=lambda c: stats_list[c].get('short_edges', 0))
        verdicts[clk] = ('CLK', 'high')
        clock_chs.discard(clk)
    if clk is None:
        notes.append('no channel shows a dominant local clock (>= 1 MHz) - '
                     'is the SIM CLK running (even if gated between bursts)?')

    # Fast-toggling channels (clocks or dense data) can never be a supply or
    # reset line; a stopped-high CLK would otherwise read as an always-high
    # supply.  Drop them from the VCC/RST candidate pools.
    def _is_signal_line(c):
        return c in clock_chs or c == clk or stats_list[c]['edges'] >= 200

    rest = [c for c in range(len(stats_list))
            if c != clk and c not in clock_chs]

    def quasi(c):
        s = stats_list[c]
        return s['edges'] <= max(50, duration * 100)

    quiet = [c for c in rest if quasi(c)]
    busy = [c for c in rest if c not in quiet]

    # DATA: busiest remaining channel, expected idle-high.  Use the
    # active-only high ratio so a gated clock's idle stretches do not drag
    # the duty reading down.
    data = None
    if busy:
        data = max(busy, key=lambda c: stats_list[c]['rate'])
        h = stats_list[data].get('high_active', stats_list[data]['high'])
        if h >= 0.80:
            conf = 'high'
        elif h >= 0.50:
            # Heavy traffic legitimately pulls the idle ratio down.
            conf = 'medium'
        else:
            conf = 'low'
            notes.append('DATA candidate reads mostly LOW '
                         '(%.0f%% high) - stuck line?' % (h * 100))
        verdicts[data] = ('DATA', conf)

    if data is None:
        notes.append('no I/O traffic seen - check DATA probe contact, '
                     'or no SIM init happened inside the window')

    # VCC vs RST among quiet channels, anchored to DATA-traffic onset.
    # Floating/unconnected pins pick up coupled glitches whose recorded
    # rise is often EARLIER than the real activation events (noise starts
    # as soon as the clock runs), so raw 'earliest rise' ordering is not
    # trustworthy.  Instead each transitioning candidate is fingerprinted:
    #   VCC  -- rises once and stays high afterwards  (post-duty >= 90 %,
    #           <= 2 falls)
    #   RST  -- pulsed: brief excursion returning to idle, timed just
    #           before the DATA burst (delta in [-0.35 s, +0.05 s])
    #   noise-- everything else: sparse blips scattered across the window,
    #           or excursions nowhere near the traffic anchor.
    t_ref = stats_list[data]['first_t'] if data is not None else None
    onsets = stats_list[data]['onsets'] if data is not None else []
    trans = [c for c in quiet if stats_list[c]['edges'] > 0
             and not _is_signal_line(c)]
    shigh = [c for c in quiet if c not in trans and stats_list[c]['high'] >= 0.90
             and not _is_signal_line(c)]
    slow = [c for c in quiet if c not in trans and c not in shigh]
    pools = {'trans': list(trans), 'shigh': list(shigh),
             'slow': list(slow), 'pulsed': [], 'sticky': []}

    def mark_ambig(lst, label):
        names = ', '.join(ch_name(c) for c in sorted(lst))
        notes.append('%s ambiguous (%s) - swap-test needed' % (label, names))
        for c in lst:
            verdicts[c] = (label, 'ambiguous')

    def feats(c):
        s = stats_list[c]
        delta = None
        if s['first_rise'] is not None and t_ref is not None:
            delta = s['first_rise'] - t_ref
        span = 0.0
        if s['first_rise'] is not None and s['last_act'] is not None:
            span = max(s['last_act'] - s['first_rise'], 0.0)
        return {'delta': delta, 'post': s['post_duty'],
                'falls': s['falls'], 'span': span}

    assigned_vcc = False
    if t_ref is not None and trans:
        pulsed, sticky, noise = [], [], []
        for c in trans:
            s = stats_list[c]
            f = feats(c)
            d, post, fl, sp = f['delta'], f['post'], f['falls'], f['span']
            # Supply lines (and floating-high pins) are mostly-high with
            # tiny dips -- never call them scatter-noise; they compete
            # via pulse evidence / interactive confirmation instead.
            supply_like = (post is not None and post >= 0.90) or \
                (post is None and
                 s.get('high_active', s['high']) >= 0.95)
            corr, _hits = reset_correlations(s['trans'], onsets,
                                             samplerate)
            scatter = s['edges'] >= 6 and sp > 0.5 * duration
            far = d is not None and abs(d) > 1.5
            if corr > 0:
                pulsed.append((-corr, s['edges'], c))
                f['corr'] = corr
            elif supply_like:
                sticky.append((s['edges'],
                               stats_list[c]['first_rise'] or 0, c))
                f['corr'] = corr
            else:
                noise.append((c, dict(f, corr=corr)))

        pulsed.sort(key=lambda t: (t[0], t[1], t[2]))
        pools['pulsed'] = [c for _co, _e, c in pulsed]
        if pulsed:
            top = pulsed[0]
            # Single-segment pulse hits stay medium confidence --
            # probe_loop corroborates across segments.
            verdicts[top[2]] = ('RST', 'medium')
            notes.append('RST evidence: %s (%d reset-correlated '
                         'pulse(s), edges=%d)'
                         % (ch_name(top[2]), -top[0], top[1]))
        sticky.sort(key=lambda t: (t[0], t[2]))
        pools['sticky'] = [c for _e, _r, c in sticky]
        if sticky:
            vcc = sticky[0][2]
            verdicts[vcc] = ('VCC', 'high')
            assigned_vcc = True
            notes.append('VCC evidence: %s (fewest edges among '
                         'always-high lines: %d)'
                         % (ch_name(vcc), sticky[0][0]))
        noise_chs = {c for c, _f in noise}
        assigned = {pulsed[0][2]} if pulsed else set()
        if sticky:
            assigned.add(sticky[0][2])
        for c in trans:
            if c not in assigned and c not in noise_chs:
                verdicts.setdefault(c, ('-', ''))
        for c, f in noise[:4]:
            dd = ('%+.2fs' % f['delta']) if f['delta'] is not None else '--'
            p = ('%.0f%%' % (f['post'] * 100)) if f['post'] is not None else '--'
            extra = ', %d reset-correlated' % f['corr'] if f['corr'] else ''
            notes.append('%s looks like noise (edges=%d, Δt_ref=%s, '
                         'post-rise duty=%s%s) - ignored'
                         % (ch_name(c), stats_list[c]['edges'], dd, p,
                            extra))
        for c in shigh + slow:
            verdicts.setdefault(c, ('-', ''))
    elif shigh:
        # No transitioning supply candidate in this window: a static-high
        # line could be the (already-powered) VCC or a floating pin, and
        # the two are indistinguishable without a power-on transition.
        # Never assert VCC from an edge-free line alone -- mark it
        # ambiguous so only transition-anchored (sticky) VCC evidence
        # reaches the cross-segment consensus.
        mark_ambig(shigh, 'VCC')
        for c in slow:
            verdicts[c] = ('-', '')
        notes.append('no VCC/RST transitions seen - trigger a card reset '
                     'during the probe window for reliable separation')
    else:
        for c in quiet:
            verdicts[c] = ('-', '')
        notes.append('no pulled-up lines seen - was the SIM powered '
                     'during the probe window?')

    return verdicts, notes, pools


def ch_name(c):
    return 'D%d' % c if c < 8 else 'A%d' % (c - 8)


def reset_correlations(trans, onsets, samplerate):
    '''Count DATA burst onsets whose preceding pulse excursion on this
    channel starts inside [RESET_WIN_BEFORE, RESET_WIN_AFTER] seconds
    relative to the onset AND CLOSES near it (within +100 ms).  The
    closing requirement excludes supply-like lines whose single rise
    precedes traffic and never returns -- those are VCC candidates, not
    reset pulses.  Orientation-agnostic: any consecutive transition
    pair is treated as one excursion.  Returns (matched_onsets,
    matched_positions).'''
    lo = -int(RESET_WIN_BEFORE * samplerate)
    hi = int(RESET_WIN_AFTER * samplerate)
    close_hi = int(0.100 * samplerate)
    hits = []
    for o in onsets:
        for k in range(len(trans) - 1):
            d_start = trans[k] - o
            if lo <= d_start <= hi:
                d_end = trans[k + 1] - o
                if abs(d_end) <= close_hi:
                    hits.append((o, trans[k]))
                    break
    return len(hits), hits


# --------------------------------------------------------------- report ---

def format_suggestion(verdicts):
    '''Return (mapping_lines, suggestion_line_or_None).

    The suggestion covers whatever subset was identified; unknown
    signals render as '?' and a partial start.sh command is still
    emitted so capture can begin on the known channels.'''
    got = {}
    for c, (v, conf) in sorted(verdicts.items()):
        base = v.split()[0]
        if base in SIGNALS and conf != 'ambiguous' and base not in got:
            got[base] = ch_name(c)
    order = ['CLK', 'DATA', 'RST', 'VCC']
    missing = [s for s in order if s not in got]
    lines = ['Detected pin mapping:' if got else 'No signals identified:']
    for s in order:
        lines.append('    %-4s -> %s' % (s, got.get(s, '?')))
    if not missing:
        cmd = './start.sh --clk=%s --data=%s --rst=%s --vcc=%s' % (
            got['CLK'], got['DATA'], got['RST'], got['VCC'])
    elif got:
        flags = ''.join(' --%s=%s' % (s.lower(), got[s])
                        for s in order if s in got)
        cmd = 'Partial: ./start.sh%s     (%s unidentified)' % (
            flags, '/'.join(missing))
    else:
        cmd = None
    return lines, cmd


def report(stats_list, samplerate, verdicts, notes, show_suggestion=True):
    print('CH   edges   rate/s   idle%%   high%%*   first-rise   verdict')
    for c, st in enumerate(stats_list):
        v, conf = verdicts.get(c, ('-', ''))
        fr = '%7.3fs' % st['first_rise'] if st['first_rise'] is not None \
            else '      --'
        h = st.get('high_active', st.get('high', 0.0))
        idle = st.get('idle_frac', 0.0)
        tag = v if not conf else '%s (%s)' % (v, conf)
        print('%-4s %6d %9.0f  %5.1f%%  %5.1f%%   %s   %s'
               % (ch_name(c), st['edges'], st['rate'], idle * 100, h * 100,
                  fr, tag))
    print('  * high%% is over active (non-idle) time; idle = no transitions '
          'on any pin')
    print()
    for n_ in notes:
        print('note: %s' % n_)
    if show_suggestion:
        lines, cmd = format_suggestion(verdicts)
        for ln in lines:
            print(ln)
        if cmd:
            print('\nSuggested: %s' % cmd)
        else:
            print('\nAdjust probes/re-plug and re-run.')


CHUNK = 32_000_000


def _active_mask(trans, n, samplerate):
    '''Bool array marking samples that are NOT in a long idle span.

    A span with zero transitions on *any* channel longer than
    IDLE_SILENCE_SEC is idle (Clock Stop Mode / no signal on any pin);
    those samples are marked False so they are excluded from high% and
    duty calculations.  The pre-first and post-last spans are idle too.'''
    active = np.ones(n, dtype=bool)
    if len(trans) == 0:
        return active
    # Prefix before the first transition and suffix after the last.
    active[:trans[0] + 1] = False
    active[trans[-1]:] = False
    if len(trans) < 2:
        return active
    gaps = np.diff(trans)
    thr = int(IDLE_SILENCE_SEC * samplerate)
    long = np.nonzero(gaps > thr)[0]
    starts = trans[:-1] + 1
    ends = trans[1:]
    for k in long:
        active[starts[k]:ends[k]] = False
    return active


def _accumulate(arr, samplerate, nch):
    accs = [ChannelAcc(samplerate) for _ in range(nch)]
    for s in range(0, len(arr), CHUNK):
        chunk = arr[s:s + CHUNK]
        for c, acc in enumerate(accs):
            acc.feed((chunk >> c) & 1, s)
    # Global activity: transitions on ANY channel (any bit of the bus).
    n = len(arr)
    changed = np.empty(n, dtype=bool)
    changed[0] = False
    changed[1:] = arr[1:] != arr[:-1]
    trans = np.nonzero(changed)[0]
    active = _active_mask(trans, n, samplerate)
    active_total = int(active.sum())
    # Per-channel high count over active (non-idle) samples only.
    high_active = [0] * nch
    if active_total:
        for s in range(0, n, CHUNK):
            chunk = arr[s:s + CHUNK]
            a = active[s:s + len(chunk)]
            for c in range(nch):
                bit = (chunk >> c) & 1
                high_active[c] += int((bit & a).sum())
    stats = [a.stats() for a in accs]
    idle_frac = (1.0 - active_total / n) if n else 0.0
    for c, st in enumerate(stats):
        st['high_active'] = (high_active[c] / active_total) if active_total \
            else 0.0
        st['idle_frac'] = idle_frac
    return stats


def classify_capture(arr, samplerate, nch):
    stats_list = _accumulate(arr, samplerate, nch)
    verdicts, notes, pools = classify(stats_list, samplerate,
                                      len(arr) / samplerate)
    return {'verdicts': verdicts, 'notes': notes, 'pools': pools,
            'stats_list': stats_list,
            'duration': len(arr) / samplerate}


def analyse(arr, samplerate, nch):
    res = classify_capture(arr, samplerate, nch)
    report(res['stats_list'], samplerate, res['verdicts'], res['notes'])


# ----------------------------------------------------------------- live ---

SIGNALS = ('CLK', 'VCC', 'RST', 'DATA')
CONF_RANK = {'low': 0, 'medium': 1, 'high': 2}


def mapping_score(verdicts):
    '''Higher is better: one point per solid signal, confidence bonus,
    ambiguity never counts.'''
    score = 0
    for _c, (v, conf) in verdicts.items():
        base = v.split()[0]
        if base in SIGNALS and conf != 'ambiguous':
            score += 1 + 0.25 * CONF_RANK.get(conf, 0)
    return score


def summary_line(verdicts, notes):
    parts = []
    for sig in SIGNALS:
        best = None
        amb = False
        for _c, (v, conf) in verdicts.items():
            if v.split()[0] != sig:
                continue
            if conf == 'ambiguous':
                amb = True
            elif best is None or CONF_RANK[conf] > CONF_RANK[best]:
                best = conf
        if best:
            parts.append('%s ✓(%s)' % (sig, best))
        elif amb:
            parts.append('%s ?(ambiguous)' % sig)
        else:
            parts.append('%s ✗' % sig)
    line = '   '.join(parts)
    if any('no I/O traffic' in n_ for n_ in notes):
        line += '   (no traffic seen on any line)'
    return line


def countdown():
    print('Trigger a SIM reset (or reboot) on the phone now.  '
          'Ctrl+C stops early.')
    for i in reversed(range(3)):
        print('  %d...' % (i + 1), flush=True)
        time.sleep(1)


def capture_live(samplerate_str='12M', seconds=2.0):
    with tempfile.NamedTemporaryFile(suffix='.sr', delete=False) as tf:
        out = tf.name
    # sigrok-cli 0.7.x spells the window options --time/--samples/--frames
    # (there is no --limit-samples); --time matches the guided-flow
    # contract directly.
    cmd = ['sigrok-cli', '-d', 'fx2lafw',
           '--config', 'samplerate=%s' % samplerate_str,
           '--time', str(int(seconds * 1000)),
           '-C', 'D0,D1,D2,D3,D4,D5,D6,D7',
           '-O', 'srzip',
           '-o', out]
    print('$ ' + ' '.join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode < 0:
            raise KeyboardInterrupt from None   # user break during capture
        sys.exit('capture failed: exit status %s' % e.returncode)
    except FileNotFoundError as e:
        sys.exit('capture failed: %s' % e)
    print('Probe saved: %s  (inspect in PulseView if the mapping looks wrong)' % out)
    return out


def resolve_signal(verdicts_seq, sig):
    '''Most recent non-ambiguous channel assigned to sig, or None.'''
    for verdicts in reversed(verdicts_seq):
        for c, (v, conf) in verdicts.items():
            if v.split()[0] == sig and conf != 'ambiguous':
                return c
    return None


def _vcc_consensus(seg_verdicts, exclude):
    '''Return the pin consistently classified as VCC across segments, or None.

    A pin must have been assigned VCC by per-segment classify() in a strict
    majority of the segments that produced any VCC (and at least 2 such
    segments), and must not be CLK/DATA/RST or user-rejected.  A floating pin
    is spurious and flaps between channels, so it never clears this bar: the
    result is either the genuine rail or nothing (honest unknown).  This
    deliberately ignores the edge-free static-high pool -- floating pins are
    the most static lines and used to win VCC precisely because they carry no
    signal.'''
    votes = {}
    any_vcc = 0
    for vd in seg_verdicts:
        picks = {c for c, (v, conf) in vd.items()
                 if v.split()[0] == 'VCC' and conf != 'ambiguous'
                 and c not in exclude}
        if picks:
            any_vcc += 1
            for c in picks:
                votes[c] = votes.get(c, 0) + 1
    if any_vcc < 2 or not votes:
        return None
    best = max(votes, key=lambda c: (votes[c], -c))
    if votes[best] * 2 <= any_vcc:
        return None
    return best


def ask_confirm(sig, ch, evidence):
    '''Interactive confirmation.  Returns True (accepted), False
    (rejected), or None when stdin is not a tty (non-interactive).'''
    if not sys.stdin.isatty():
        return None
    if ch is None:
        return None
    while True:
        try:
            ans = input('Confirm %s -> %s? %s[Y/n] '
                        % (sig, ch_name(ch), evidence)).strip().lower()
        except EOFError:
            return None
        if ans in ('', 'y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False


def ask_confirm_map(verdicts):
    '''Single Y/n confirm of the whole pin mapping.  Returns True (accepted),
    False (rejected), or None when stdin is not a tty (non-interactive).'''
    if not sys.stdin.isatty():
        return None
    while True:
        try:
            ans = input('Accept this pin mapping? [Y/n] ').strip().lower()
        except EOFError:
            return None
        if ans in ('', 'y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False


def probe_loop(samplerate_str='24M', seg_seconds=3.0, max_segments=20):
    sr_int = parse_rate(samplerate_str)
    cap = int(sr_int * seg_seconds * 1.1)
    print('Probe: %s, all channels, %.1f s segments, up to %d tries.'
          % (samplerate_str, seg_seconds, max_segments))
    countdown()
    best = None
    agg = None               # ch -> {'edges', 'rst'}
    seg_verdicts = []        # per-segment verdict dicts, in order
    rejected = {'RST': set(), 'VCC': set()}
    try:
        for seg in range(1, max_segments + 1):
            print('\n=== segment %d ===' % seg)
            path = capture_live(samplerate_str, seg_seconds)
            arr, srate, nch = load_sr(path, cap)
            if len(arr) >= cap:
                print('note: segment truncated at %d samples '
                      '(raise --max-samples or lower --seconds)'
                      % len(arr))
            res = classify_capture(arr, srate, nch)
            res['score'] = mapping_score(res['verdicts'])
            seg_verdicts.append(res['verdicts'])
            print(summary_line(res['verdicts'], res['notes']))
            if best is None or res['score'] >= best['score']:
                best = dict(res, srate=srate, nsamp=len(arr), seg=seg)

            # ---- cross-segment evidence aggregation ----
            if agg is None:
                agg = {c: {'edges': 0, 'rst': 0} for c in range(nch)}
            pools = res['pools']
            for c in agg:
                agg[c]['edges'] += res['stats_list'][c]['edges']
            for c in pools.get('pulsed', []):
                agg[c]['rst'] += 1

            clk_ch = resolve_signal(seg_verdicts, 'CLK')
            data_ch = resolve_signal(seg_verdicts, 'DATA')
            taken = {clk_ch, data_ch}

            # Ranked candidates from aggregated evidence.
            rst_ranked = sorted(
                (c for c, a in agg.items()
                 if a['rst'] > 0 and c not in taken
                 and c not in rejected['RST']),
                key=lambda c: (-agg[c]['rst'], agg[c]['edges']))
            # Early finalize: once CLK and DATA are both resolved we stop
            # probing.  RST/VCC are optional for decoding (RST only enables
            # warm-reset re-arm; VCC is informational), so we do not keep
            # hunting for them -- we finalize with whichever were found.
            if clk_ch is not None and data_ch is not None:
                rst_top = rst_ranked[0] if rst_ranked else None
                vcc_top = _vcc_consensus(
                    seg_verdicts,
                    (taken | rejected['VCC']
                     | ({rst_top} if rst_top is not None else set())))
                final = {}
                final[clk_ch] = ('CLK', 'high')
                final[data_ch] = ('DATA', 'high')
                if rst_top is not None:
                    final[rst_top] = ('RST', 'medium')
                if vcc_top is not None:
                    final[vcc_top] = ('VCC', 'low')
                lines, cmd = format_suggestion(final)
                for ln in lines:
                    print(ln)
                if cmd:
                    print('\nSuggested: %s' % cmd)
                if not sys.stdin.isatty():
                    print('CLK+DATA resolved (headless) - stopping.')
                    return final
                ok = ask_confirm_map(final)
                if ok is False:
                    print('Mapping rejected - re-probing...', flush=True)
                    continue
                print('\nMapping accepted at segment %d.' % seg)
                return final
            if seg < max_segments:
                print('Trigger reset again if needed...', flush=True)
                time.sleep(1)
    except KeyboardInterrupt:
        print('\n(stopped by user)')
    if best is None or agg is None:
        sys.exit('no usable segments captured')

    # ---- final resolution -------------------------------------------------
    final = {}
    open_q = []
    clk_ch = resolve_signal(seg_verdicts, 'CLK')
    data_ch = resolve_signal(seg_verdicts, 'DATA')
    if clk_ch is not None:
        final[clk_ch] = ('CLK', 'high')
    else:
        open_q.append('CLK unidentified')
    if data_ch is not None:
        final[data_ch] = ('DATA', 'high')
    else:
        open_q.append('DATA unidentified')

    taken = {clk_ch, data_ch}
    rst_ranked = sorted((c for c, a in agg.items()
                         if a['rst'] > 0 and c not in taken
                         and c not in rejected['RST']),
                        key=lambda c: (-agg[c]['rst'], agg[c]['edges']))
    if rst_ranked:
        final[rst_ranked[0]] = ('RST', 'medium')
        open_q.append('RST candidate %s (%d pulse segment(s)) - verify'
                      % (ch_name(rst_ranked[0]), agg[rst_ranked[0]]['rst']))
    else:
        open_q.append('RST never pulsed - trigger resets inside segments')

    vcc_top = _vcc_consensus(
        seg_verdicts,
        (taken | rejected['VCC']
         | ({rst_ranked[0]} if rst_ranked else set())))
    if vcc_top is not None:
        final[vcc_top] = ('VCC', 'low')
        open_q.append('VCC candidate %s (consistent across segments) - verify'
                      % ch_name(vcc_top))
    else:
        open_q.append('VCC unresolved - no consistent VCC evidence; '
                      'static-high lines are not positively identifiable '
                      '(may be floating)')

    print('\nBest result table: segment %d\n' % best['seg'])
    report(best['stats_list'], best['srate'],
           best['verdicts'], best['notes'], show_suggestion=False)
    lines, _cmd = format_suggestion(final)
    for ln in lines:
        print(ln)
    for q in open_q:
        print('open: %s' % q)


# -------------------------------------------------------------- selftest --

def synth(n, sr, clk_ch=None, data_ch=None, rst_ch=None, vcc_ch=None,
          gate_rst=True, pre_high=False, gate_clk=False):
    '''Build an 8-channel packed stream with known signal placement.'''
    t = np.arange(n) / sr
    chans = {}
    if gate_clk:
        # Clock Stop Mode: CLK runs only inside the transaction window and
        # is held HIGH (stop-high) the rest of the time -- exactly the case
        # that used to confuse high/low-time based detection.
        clk = np.ones(n, dtype=np.uint8)
        window = (t >= 0.10) & (t < 0.35)
        clk[window] = (((t[window] * 2e6).astype(np.int64)) % 2)
    else:
        clk = (((t * 2e6).astype(np.int64)) % 2).astype(np.uint8)
    chans['clk'] = clk
    vcc = (t >= 0.05).astype(np.uint8)
    rst = ((t >= 0.10) & (t < 0.15)).astype(np.uint8)
    if pre_high:
        rst = np.ones(n, dtype=np.uint8)      # no transitions at all
        vcc = np.ones(n, dtype=np.uint8)
    data = np.ones(n, dtype=np.uint8)
    burst = (t >= 0.15) & (t < 0.30)
    data[burst] = (((t[burst] * 1e5).astype(np.int64)) % 2)
    chans['data'] = data
    chans['rst'] = rst
    chans['vcc'] = vcc
    mapping = {'clk': clk_ch, 'data': data_ch, 'rst': rst_ch, 'vcc': vcc_ch}
    arr = np.zeros(n, dtype=np.uint8)
    for sig, ch in mapping.items():
        if ch is not None:
            arr |= chans[sig] << ch
    return arr


def _classify_arr(arr, sr):
    stats = _accumulate(arr, sr, 8)
    v, notes, _pools = classify(stats, sr, len(arr) / sr)
    return v, notes


def selftest():
    failures = []

    # parse_rate: CLI shorthand and .sr metadata spellings alike.
    for s, want in [('12M', 12_000_000), ('12MHz', 12_000_000),
                    ('25 MHz', 25_000_000), ('400kHz', 400_000),
                    ('400 kHz', 400_000), ('1000', 1000)]:
        got = parse_rate(s)
        ok = got == want
        print('selftest parse_rate %-9s: %s (%d)'
              % (repr(s), 'PASS' if ok else 'FAIL', got))
        if not ok:
            failures.append('parse_rate %r' % s)

    sr = 12_000_000
    n = sr // 2                       # 0.5 s window keeps it fast

    # Case 1: scrambled but complete mapping.
    arr = synth(n, sr, clk_ch=5, data_ch=3, rst_ch=0, vcc_ch=4)
    v, notes = _classify_arr(arr, sr)
    got = {verdict.split()[0]: ch_name(c) for c, (verdict, _) in v.items()}
    want = {'CLK': 'D5', 'DATA': 'D3', 'RST': 'D0', 'VCC': 'D4'}
    ok = all(got.get(k) == want[k] for k in want)
    print('selftest scrambled-mapping: %s (got %s)' % ('PASS' if ok else 'FAIL', got))
    if not ok:
        failures.append('scrambled mapping')

    # Case 1b: gated / stopped CLK (Clock Stop Mode) must still detect CLK
    # -- the prior average-rate heuristic used to miss it and misread the
    # stopped-high clock as a supply line.
    arr = synth(n, sr, clk_ch=5, data_ch=3, rst_ch=0, vcc_ch=4, gate_clk=True)
    v, notes = _classify_arr(arr, sr)
    got = {verdict.split()[0]: ch_name(c) for c, (verdict, _) in v.items()}
    ok = (got.get('CLK') == 'D5' and got.get('DATA') == 'D3'
          and got.get('RST') == 'D0' and got.get('VCC') == 'D4')
    # Idle-aware metrics: the gated CLK must read ~50% duty over its active
    # (non-idle) windows, and most of the capture must be idle.
    res = classify_capture(arr, sr, 8)
    clk_c = next(c for c, (vv, _) in res['verdicts'].items()
                 if vv.split()[0] == 'CLK')
    st = res['stats_list'][clk_c]
    ha = st['high_active']
    idle = st['idle_frac']
    ok = ok and (0.40 <= ha <= 0.60) and idle > 0.2
    print('selftest gated-clk (stop timer): %s (got %s, high_active=%.2f, '
          'idle_frac=%.2f)' % ('PASS' if ok else 'FAIL', got, ha, idle))
    if not ok:
        failures.append('gated-clk case')

    # Case 2: VCC/RST static-high whole window -> ambiguity must be flagged.
    arr = synth(n, sr, clk_ch=2, data_ch=6, rst_ch=0, vcc_ch=4, pre_high=True)
    v, notes = _classify_arr(arr, sr)
    amb = [c for c, (verdict, conf) in v.items() if conf == 'ambiguous']
    ok = len(amb) == 2 and v[2][0] == 'CLK' and v[6][0].startswith('DATA')
    print('selftest static-pair ambiguity: %s (ambiguous=%s)'
          % ('PASS' if ok else 'FAIL', [ch_name(c) for c in amb]))
    if not ok:
        failures.append('ambiguity case')

    # Case 3: report() must emit the mapping block AND the suggested
    # command for a complete detection.  (A lowercase/uppercase key
    # mismatch once made the Suggested line unreachable -- invisible to
    # headless tests because they stubbed report() out.)
    import io
    import contextlib

    stats = [dict(edges=10, rate=10, high=1.0, median_gap=3,
                  first_rise=0.01, last_act=0.02) for _ in range(8)]
    complete = {2: ('CLK', 'high'), 3: ('DATA', 'high'),
                4: ('RST', 'high'), 5: ('VCC', 'high')}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(stats, 12_000_000, complete, [])
    out = buf.getvalue()
    ok = ('Suggested:' in out and '--clk=D2' in out and '--vcc=D5' in out
          and 'Detected pin mapping:' in out)
    print('selftest report-suggestion : %s' % ('PASS' if ok else 'FAIL'))
    if not ok:
        failures.append('report suggestion')

    # Case 4: partial mapping still yields a usable partial command.
    partial = {2: ('CLK', 'high'), 3: ('DATA', 'high')}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(stats, 12_000_000, partial, [])
    out = buf.getvalue()
    ok = ('Partial: ./start.sh --clk=D2 --data=D3' in out
          and 'RST/VCC unidentified' in out)
    print('selftest report-partial    : %s' % ('PASS' if ok else 'FAIL'))
    if not ok:
        failures.append('report partial')

    # Case 5: floating/unconnected pins emit sparse coupled blips that
    # START as early as the clock -- raw 'earliest rise' ordering used
    # to hand VCC/RST to those ghosts (observed on real hardware).
    arr = np.zeros(n, dtype=np.uint8)
    t = np.arange(n) / sr
    arr |= ((((t * 2e6).astype(np.int64)) % 2)).astype(np.uint8) << 1   # CLK D1
    d = np.ones(n, dtype=np.uint8)
    burst = (t >= 0.15) & (t < 0.30)
    d[burst] = (((t[burst] * 1e5).astype(np.int64)) % 2)
    arr |= d << 6                                                        # DATA D6
    arr |= (((t >= 0.10) & (t < 0.15)).astype(np.uint8)) << 0            # RST D0
    arr |= ((t >= 0.05).astype(np.uint8)) << 4                           # VCC D4
    # two floating pins: thin blips scattered across the whole window
    for ch, offs in ((5, [0.02, 0.09, 0.21, 0.33, 0.41, 0.47]),
                     (7, [0.01, 0.06, 0.18, 0.27, 0.38, 0.49])):
        for o in offs:
            i0 = int(o * n)
            arr[i0:i0 + 40] |= (1 << ch)
    v, notes = _classify_arr(arr, sr)
    got = {verdict.split()[0]: ch_name(c) for c, (verdict, conf)
           in v.items() if conf != 'ambiguous'}
    want = {'CLK': 'D1', 'DATA': 'D6', 'RST': 'D0', 'VCC': 'D4'}
    ok = all(got.get(k) == want[k] for k in want)
    noisy_flagged = sum(1 for _c, (_vv, cf) in v.items() if cf != 'ambiguous'
                        ) >= 4
    print('selftest floating-noise     : %s (got %s)'
          % ('PASS' if ok else 'FAIL', got))
    if not ok or not noisy_flagged:
        failures.append('floating-noise case')

    # Case 6: _vcc_consensus gating (the multi-segment VCC vote).
    # Floating pins flap between channels across segments and must never
    # clear the bar; only a pin consistently classified VCC in a strict
    # majority (and >= 2 segments) is accepted.
    taken = {1, 6, 0}   # CLK, DATA, RST
    base = {1: ('CLK', 'high'), 6: ('DATA', 'high'), 0: ('RST', 'medium')}
    seg_d2 = {**base, 2: ('VCC', 'low')}
    seg_d5 = {**base, 5: ('VCC', 'low')}
    seg_d4 = {**base, 4: ('VCC', 'high')}
    ok = (_vcc_consensus([base, base], taken) is None          # no VCC ever
          and _vcc_consensus([seg_d2], taken) is None          # single segment
          and _vcc_consensus([seg_d2, seg_d5], taken) is None  # flapping D2/D5
          and _vcc_consensus([seg_d4, seg_d4], taken) == 4     # consistent
          and _vcc_consensus([seg_d4, seg_d4, seg_d2], taken) == 4)  # 2/3
    print('selftest vcc-consensus      : %s' % ('PASS' if ok else 'FAIL'))
    if not ok:
        failures.append('vcc-consensus case')

    if failures:
        sys.exit('SELFTEST FAILED: %s' % ', '.join(failures))
    print('selftest OK')


# ------------------------------------------------------------------ main --

def main():
    # Windows consoles default to legacy codepages that cannot render
    # the ✓/✗ markers used in summaries; degrade gracefully instead of
    # raising UnicodeEncodeError mid-report.
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('capture', nargs='?', help='.sr capture file')
    ap.add_argument('--live', action='store_true',
                    help='probe live (default when no capture file is given)')
    ap.add_argument('--samplerate', default='24M')
    ap.add_argument('--seconds', type=float, default=3.0,
                    help='segment length in seconds (default: %(default)s)')
    ap.add_argument('--max-segments', type=int, default=20,
                    help='stop after this many segments (default: %(default)s)')
    ap.add_argument('--max-samples', type=int, default=400_000_000,
                    help='cap for offline captures (default: %(default)s)')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return
    if args.capture and args.live:
        ap.error('pass either a capture file or --live, not both')
    if args.capture:
        arr, samplerate, nch = load_sr(path=args.capture,
                                       max_samples=args.max_samples)
        print('loaded %s: %d samples @ %s, %d channels\n'
              % (args.capture, len(arr), samplerate, nch))
        analyse(arr, samplerate, nch)
    else:
        # Live probing is the primary use -- bare invocation suffices.
        probe_loop(args.samplerate, args.seconds, args.max_segments)


if __name__ == '__main__':
    main()
