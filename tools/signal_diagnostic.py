#!/usr/bin/env python3
"""Lower-level signal quality diagnostics for .sr trace files.

Reads a sigrok .sr file and reports per-signal measurements:
  CLK  — frequency, duration, frequency changes
  RST  — transitions, stability (noisy = ignore)
  VCC  — transitions, stability (noisy = ignore)
  DATA — oscillations, correlation with CLK

Usage:
  python3 tools/signal_diagnostic.py trace.sr [--clk CLK] [--data DATA] [--rst RST] [--vcc VCC]

Channel names must match the probe names in the .sr metadata
(e.g. CLK, DATA, RST, VCC or D0, D1, etc.).
"""

import argparse
import statistics
import sys
import zipfile


# ---------------------------------------------------------------------------
# .sr file reading
# ---------------------------------------------------------------------------

def parse_sr_metadata(path):
    """Return dict with 'samplerate', 'probes' (probe_num -> name), 'unitsize'."""
    with zipfile.ZipFile(path, 'r') as zf:
        meta = zf.read('metadata').decode()
    info = {'probes': {}}
    for line in meta.splitlines():
        line = line.strip()
        if line.startswith('samplerate'):
            val = line.split('=', 1)[1].strip()
            if val.endswith(' MHz'):
                info['samplerate'] = float(val[:-4]) * 1e6
            elif val.endswith(' kHz'):
                info['samplerate'] = float(val[:-4]) * 1e3
            elif val.endswith(' Hz'):
                info['samplerate'] = float(val[:-3])
            else:
                info['samplerate'] = float(val)
        elif line.startswith('unitsize'):
            info['unitsize'] = int(line.split('=', 1)[1].strip())
        elif line.startswith('total probes'):
            info['total_probes'] = int(line.split('=', 1)[1].strip())
        elif line.startswith('probe'):
            parts = line.split('=', 1)
            num = int(parts[0][5:])
            info['probes'][num] = parts[1].strip()
    return info


def read_sr_channels(path, max_samples=None, step=1, start_at=0):
    """Yield (sample_index, byte_value) tuples from logic chunks.

    Chunks are read in numeric order (logic-1-1, logic-1-2, ..., logic-1-N).
    Args:
        max_samples: Stop after yielding this many samples (None = all).
        step: Read every Nth byte from each chunk (1 = every byte).
        start_at: Skip to this sample index before yielding.
    """
    with zipfile.ZipFile(path, 'r') as zf:
        chunk_names = [n for n in zf.namelist() if n.startswith('logic-1-')]
        chunk_names.sort(key=lambda n: int(n.split('-')[-1]))
        first_data = zf.read(chunk_names[0])
        chunk_size = len(first_data)
        idx = 0
        for chunk in chunk_names:
            if idx + chunk_size <= start_at:
                idx += chunk_size
                continue
            data = zf.read(chunk)
            for i in range(0, len(data), step):
                if idx < start_at:
                    idx += step
                    continue
                if max_samples is not None and (idx - start_at) >= max_samples:
                    return
                yield idx, data[i]
                idx += step


def get_channel_bit(metadata, channel_name):
    """Return the bit position (0-indexed) for a channel name, or None."""
    for probe_num, name in metadata['probes'].items():
        if name == channel_name:
            return probe_num - 1  # probe 1 = bit 0, probe 2 = bit 1, ...
    return None


# ---------------------------------------------------------------------------
# Signal measurement helpers
# ---------------------------------------------------------------------------

def measure_clk(channel_data, sr):
    """Measure CLK frequency from transitions. Returns dict."""
    if not channel_data:
        return {'ok': False, 'reason': 'no data'}

    # Find all rising edges
    edges = []
    for i in range(1, len(channel_data)):
        if channel_data[i - 1] == 0 and channel_data[i] == 1:
            edges.append(i)

    if len(edges) < 2:
        return {
            'ok': False,
            'reason': f'only {len(edges)} rising edges (need >= 2)',
            'transitions': len(edges),
        }

    # Frequency from edge spacings
    spacings = [edges[i] - edges[i - 1] for i in range(1, len(edges))]
    median_spc = statistics.median(spacings)
    freq = sr / median_spc if median_spc > 0 else 0

    # Duration of CLK activity (first to last edge)
    duration_s = (edges[-1] - edges[0]) / sr

    # Frequency change detection: split into 4 windows, compare median
    freq_change = None
    if len(spacings) >= 20:
        n = len(spacings)
        q1 = statistics.median(spacings[:n // 4])
        q4 = statistics.median(spacings[3 * n // 4:])
        if q1 > 0 and q4 > 0:
            f1 = sr / q1
            f4 = sr / q4
            change_pct = abs(f1 - f4) / max(f1, f4) * 100
            if change_pct > 10:
                freq_change = f'{change_pct:.0f}% change ({f1/1e6:.2f} -> {f4/1e6:.2f} MHz)'

    return {
        'ok': True,
        'rising_edges': len(edges),
        'frequency_mhz': freq / 1e6,
        'median_period_samples': median_spc,
        'duration_ms': duration_s * 1000,
        'freq_change': freq_change,
    }


def measure_rst(channel_data, sr):
    """Measure RST transitions. Returns dict."""
    if not channel_data:
        return {'ok': False, 'reason': 'no data'}

    transitions = 0
    for i in range(1, len(channel_data)):
        if channel_data[i] != channel_data[i - 1]:
            transitions += 1

    stable_pct = (1 - transitions / len(channel_data)) * 100 if channel_data else 100
    noisy = transitions > len(channel_data) * 0.01  # >1% transitions = noisy

    return {
        'ok': True,
        'transitions': transitions,
        'stable_pct': stable_pct,
        'noisy': noisy,
    }


def measure_vcc(channel_data, sr):
    """Measure VCC transitions. Returns dict."""
    return measure_rst(channel_data, sr)  # Same analysis


def measure_data(channel_data, clk_data, sr):
    """Measure DATA signal and CLK-DATA correlation. Returns dict."""
    if not channel_data:
        return {'ok': False, 'reason': 'no data'}

    # Count transitions
    transitions = 0
    for i in range(1, len(channel_data)):
        if channel_data[i] != channel_data[i - 1]:
            transitions += 1

    # Correlation with CLK: count how many CLK rising edges also have DATA transitions
    clk_data_corr = None
    if clk_data and len(clk_data) == len(channel_data):
        matching = 0
        total_clk_edges = 0
        for i in range(1, len(channel_data)):
            if clk_data[i - 1] == 0 and clk_data[i] == 1:  # CLK rising edge
                total_clk_edges += 1
                if channel_data[i] != channel_data[i - 1]:
                    matching += 1
        if total_clk_edges > 0:
            clk_data_corr = f'{matching}/{total_clk_edges} ({matching / total_clk_edges * 100:.0f}%)'

    return {
        'ok': True,
        'transitions': transitions,
        'clk_data_correlation': clk_data_corr,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_analysis(path, clk_name, data_name, rst_name, vcc_name):
    """Run full signal analysis on a .sr file. Returns results dict.

    Passes:
    1. First WINDOW samples for initial signal check
    2. If CLK quiet, scan for first activity (check every 100th sample)
    3. WINDOW around first activity for CLK frequency, RST/VCC, DATA correlation
    4. Full trace (every 10th sample) for total transition counts
    """
    meta = parse_sr_metadata(path)
    sr = meta['samplerate']

    clk_bit = get_channel_bit(meta, clk_name)
    data_bit = get_channel_bit(meta, data_name)
    rst_bit = get_channel_bit(meta, rst_name)
    vcc_bit = get_channel_bit(meta, vcc_name)

    WINDOW = 5_000_000  # 5M samples = 312ms at 16 MHz (detailed measurements)

    # Pass 1: first WINDOW samples
    clk_win = []
    data_win = []
    rst_win = []
    vcc_win = []
    has_clk_activity = False
    for _, bv in read_sr_channels(path, max_samples=WINDOW):
        if clk_bit is not None:
            v = (bv >> clk_bit) & 1
            clk_win.append(v)
            if v == 1:
                has_clk_activity = True
        if data_bit is not None:
            data_win.append((bv >> data_bit) & 1)
        if rst_bit is not None:
            rst_win.append((bv >> rst_bit) & 1)
        if vcc_bit is not None:
            vcc_win.append((bv >> vcc_bit) & 1)

    # Pass 2: if CLK was quiet, scan for first activity
    first_activity_sample = 0
    if not has_clk_activity and clk_bit is not None:
        # Scan at every 10000th sample to find where CLK starts
        scan_step = 10000
        scan_limit = 2_000_000_000  # 2G samples
        for sample_idx, bv in read_sr_channels(path, max_samples=scan_limit, step=scan_step):
            v = (bv >> clk_bit) & 1
            if v == 1:
                first_activity_sample = max(0, sample_idx - scan_step * 5)
                break

        if first_activity_sample > 0:
            # Re-read WINDOW samples starting from first activity (with chunk-skip)
            clk_win = []
            data_win = []
            for _, bv in read_sr_channels(path, max_samples=WINDOW, start_at=first_activity_sample):
                if clk_bit is not None:
                    clk_win.append((bv >> clk_bit) & 1)
                if data_bit is not None:
                    data_win.append((bv >> data_bit) & 1)

    # Pass 3: full trace, every 10th sample — count total transitions
    total_step_samples = 0
    prev = {}
    trans = {}
    for _, bv in read_sr_channels(path, step=10):
        total_step_samples += 1
        for name, bit in [('clk', clk_bit), ('data', data_bit), ('rst', rst_bit), ('vcc', vcc_bit)]:
            if bit is None:
                continue
            v = (bv >> bit) & 1
            if name in prev and v != prev[name]:
                trans[name] = trans.get(name, 0) + 1
            prev[name] = v

    real_total = total_step_samples * 10
    duration_s = real_total / sr

    results = {
        'samplerate_mhz': sr / 1e6,
        'total_samples': real_total,
        'duration_ms': duration_s * 1000,
        'channels_found': {
            'CLK': clk_name if clk_bit is not None else None,
            'DATA': data_name if data_bit is not None else None,
            'RST': rst_name if rst_bit is not None else None,
            'VCC': vcc_name if vcc_bit is not None else None,
        },
        'first_activity_sample': first_activity_sample,
    }

    results['CLK'] = measure_clk(clk_win, sr) if clk_win else {
        'ok': False, 'reason': f'channel "{clk_name}" not found'}

    rst_t = trans.get('rst', 0)
    results['RST'] = {
        'ok': True, 'transitions': rst_t,
        'stable_pct': (1 - rst_t / max(real_total, 1)) * 100,
        'noisy': rst_t > real_total * 0.01,
    } if rst_bit is not None else {
        'ok': False, 'reason': f'channel "{rst_name}" not found'}

    vcc_t = trans.get('vcc', 0)
    results['VCC'] = {
        'ok': True, 'transitions': vcc_t,
        'stable_pct': (1 - vcc_t / max(real_total, 1)) * 100,
        'noisy': vcc_t > real_total * 0.01,
    } if vcc_bit is not None else {
        'ok': False, 'reason': f'channel "{vcc_name}" not found'}

    results['DATA'] = measure_data(data_win, clk_win, sr) if data_win else {
        'ok': False, 'reason': f'channel "{data_name}" not found'}
    # Override DATA transitions with full-trace count (window may miss late activity)
    if data_bit is not None:
        results['DATA']['transitions'] = trans.get('data', 0)

    return results


def print_results(results):
    """Pretty-print signal diagnostic results."""
    print(f"  Sample rate:    {results['samplerate_mhz']:.1f} MHz")
    print(f"  Samples:        {results['total_samples']}")
    print(f"  Duration:       {results['duration_ms']:.1f} ms")
    found = results['channels_found']
    print(f"  Channels:       CLK={found['CLK']} DATA={found['DATA']} RST={found['RST']} VCC={found['VCC']}")
    if results.get('first_activity_sample', 0) > 0:
        print(f"  First activity: sample {results['first_activity_sample']}")
    print()

    # CLK
    clk = results['CLK']
    print("  CLK:")
    if clk.get('ok'):
        print(f"    Frequency:    {clk['frequency_mhz']:.2f} MHz")
        print(f"    Period:       {clk['median_period_samples']:.1f} samples")
        print(f"    Rising edges: {clk['rising_edges']}")
        print(f"    Duration:     {clk['duration_ms']:.1f} ms")
        if clk.get('freq_change'):
            print(f"    WARNING:      {clk['freq_change']}")
    else:
        print(f"    FAIL:         {clk.get('reason', 'unknown')}")

    # RST
    rst = results['RST']
    print("  RST:")
    if rst.get('ok'):
        print(f"    Transitions:  {rst['transitions']}")
        print(f"    Stable:       {rst['stable_pct']:.1f}%")
        if rst['noisy']:
            print(f"    WARNING:      noisy (>{1}% transitions) — consider --rst=ignore")
    else:
        print(f"    Not present:  {rst.get('reason', 'n/a')}")

    # VCC
    vcc = results['VCC']
    print("  VCC:")
    if vcc.get('ok'):
        print(f"    Transitions:  {vcc['transitions']}")
        print(f"    Stable:       {vcc['stable_pct']:.1f}%")
        if vcc['noisy']:
            print(f"    WARNING:      noisy (>{1}% transitions) — consider --vcc=ignore")
    else:
        print(f"    Not present:  {vcc.get('reason', 'n/a')}")

    # DATA
    data = results['DATA']
    print("  DATA:")
    if data.get('ok'):
        print(f"    Transitions:  {data['transitions']}")
        if data.get('clk_data_correlation'):
            print(f"    CLK corr:     {data['clk_data_correlation']}")
    else:
        print(f"    FAIL:         {data.get('reason', 'unknown')}")
    print()


def main():
    parser = argparse.ArgumentParser(description='Signal quality diagnostic for .sr traces')
    parser.add_argument('sr_file', help='Path to .sr file')
    parser.add_argument('--clk', default='CLK', help='CLK channel name (default: CLK)')
    parser.add_argument('--data', default='DATA', help='DATA channel name (default: DATA)')
    parser.add_argument('--rst', default='RST', help='RST channel name (default: RST)')
    parser.add_argument('--vcc', default='VCC', help='VCC channel name (default: VCC)')
    args = parser.parse_args()

    results = run_analysis(args.sr_file, args.clk, args.data, args.rst, args.vcc)
    print(f"Signal diagnostic: {args.sr_file}")
    print_results(results)


if __name__ == '__main__':
    main()
