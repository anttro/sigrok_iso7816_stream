#!/usr/bin/env python3
"""Compare a decoded GSMTAP pcap against a PC/SC reader APDU log.

Both describe the same ISO 7816-4 exchange stream: the reader log gives
one line per exchange as `C-APDU => R-APDU`, and the decoder emits each
exchange as one GSMTAP event carrying concatenated `C-APDU + R-APDU`.

The capture is usually a TIME-SLICE of the reader session (capture may
start mid-session), and the reader SDK does NOT surface CAT/proactive
traffic (TERMINAL PROFILE, FETCH, STATUS, ENVELOPE, ...) -- so the pcap
is the reader log's exchange sequence, interspersed with extra
proactive/polling exchanges.  We therefore align via longest-common-
subsequence, not greedy prefix matching.

Degradation metrics:
  - BAD_FCS: decoder-flagged desynced APDUs (GSMTAP_FLAG_BAD_FCS)
  - CONCAT: packets that embed complete exchanges (mis-frame swallowed
    several real exchanges into one)
  - payload mismatches: LCS-matched pairs where bytes differ
  - suspicious CLA: APDUs with unexpected CLA values

Usage:
  python3 tools/vs_reader.py <reader.log> <capture.pcap>
  python3 tools/vs_reader.py --pcap-only <capture.pcap>   (no reader log)
"""

import argparse
import difflib
import re
import struct
import sys

# CAT commands the PC/SC reader SDK handles internally and does not log.
CAT_INS = {
    0x10,  # TERMINAL PROFILE
    0x12,  # FETCH
    0x14,  # TERMINAL RESPONSE
    0x24,  # GET INPUT
    0x26,  # PROVIDE LOCAL INFO
    0xC2,  # ENVELOPE
    0xF2,  # STATUS
}

# GSMTAP_FLAG_BAD_FCS from gsmtap_stream.py
GSMTAP_FLAG_BAD_FCS = 0x01

# Valid CLA values for ISO 7816 / 3GPP.  Mirror of plausible_cla in pd.py:
# interindustry structures (high nibble 0x0/0x1/0x4/0x5), which covers the
# logical-channel classes 0x01-0x03 (e.g. the command after MANAGE CHANNEL
# opens channel 1), plus the proprietary SIM/UICC CAT classes.
def _plausible_cla(cla):
    if not (cla & 0x80):
        return (cla & 0xF0) in (0x00, 0x10, 0x40, 0x50)
    return cla in (0x80, 0x84, 0xA0, 0xB0)


VALID_CLA = frozenset(cla for cla in range(256) if _plausible_cla(cla))

# ISO 7816-3 T=0 max TPDU length: header(5) + procedure bytes + 255 data + SW(2)
MAX_TPDU_LEN = 271

# --- embedded-exchange (CONCAT) detector ---
# A byte-drop mis-frame can swallow several real T=0 exchanges into one
# structurally valid packet: each swallowed header survives verbatim in the
# data region, followed by its P3 data bytes and an interior status word.
# These constants bound detector precision (empirically tuned on all 10
# example traces: 0 hits on clean traces, every Samsung/xiaomi family hit).
EMBEDDED_CLA = VALID_CLA
# Commands that actually occur on these cards' bus (T=0 + STK/CAT).
EMBEDDED_INS = frozenset((
    0x12, 0x14, 0x20, 0x44, 0x70, 0x88,
    0xA2, 0xA4, 0xB0, 0xB2, 0xB6,
    0xC0, 0xC2, 0xCA, 0xCB, 0xD6, 0xDC, 0xF2,
))
# Real SW1 values that are not also frequent data bytes (BER-TLV tags).
EMBEDDED_SW1 = frozenset((
    0x60, 0x61, 0x62, 0x63, 0x67, 0x68, 0x69,
    0x6A, 0x6B, 0x6D, 0x6E, 0x6F, 0x90, 0x91,
    0x93, 0x98, 0x99,
))
EMBEDDED_SW1_SLACK = 3  # SW1 search window after the nominal data end


def embedded_exchanges(buf):
    """Return [(header_start, sw1_index), ...] for complete T=0 exchanges
    embedded inside a packet's data region (index 5 onward).

    Pattern: header (CLA INS P1 P2 P3) + P3 data bytes + interior SW1/SW2
    before the packet's own final status word.  CLA must be structurally
    valid (same rule as _plausible_cla); INS must be a real command byte;
    SW1 is accepted within a small slack window after the nominal data end
    and must be interior (trailing bytes follow it).
    """
    n = len(buf)
    out = []
    if n < 12:
        return out
    q = 5
    while q <= n - 9:
        s = q
        cla, ins, _p1, _p2, p3 = buf[s:s + 5]
        if cla not in EMBEDDED_CLA:
            q += 1
            continue
        if ins not in EMBEDDED_INS:
            q += 1
            continue
        if p3 == 0:
            q += 1
            continue
        d1 = s + 5 + p3
        if d1 + 3 > n:
            q += 1
            continue
        sw1 = -1
        for e in range(d1, min(n - 1, d1 + EMBEDDED_SW1_SLACK + 1)):
            if buf[e] in EMBEDDED_SW1:
                sw1 = e
                break
        if sw1 == -1 or sw1 >= n - 2:
            q += 1
            continue
        out.append((s, sw1))
        q += 1
    return out


def _plausible_sw(sw1):
    return (0x60 <= sw1 <= 0x6F) or (0x90 <= sw1 <= 0x9F)


def _plausible_ins(ins):
    if ins == 0x00:
        return False
    if (ins & 0xF0) == 0x60 or (ins & 0xF0) == 0x90:
        return False
    if (ins & 0x01) != 0:
        return False
    return True


def validate_t0_apdu(packet):
    '''See validate_t0_apdu in pd.py; same rules, duplicated here so the
    standalone vs_reader can classify pcap entries without importing the
    sigrok decoder module.'''
    n = len(packet)

    if n < 7:
        return (False, 'too short (< 7)')
    if n > MAX_TPDU_LEN:
        return (False, 'exceeds T=0 max length')

    cla = packet[0]
    ins = packet[1]
    sw1 = packet[-2]

    if cla not in VALID_CLA:
        return (False, 'invalid CLA')
    if not _plausible_ins(ins):
        return (False, 'invalid INS')
    if not _plausible_sw(sw1):
        return (False, 'invalid SW1')

    return (True, None)


def parse_reader_log(path):
    """Return list of exchange byte-strings (C-APDU + R-APDU concatenated)."""
    exchanges = []
    for line in open(path, errors='ignore'):
        m = re.match(r'^T0: .* TPDU: ([0-9a-fA-F]+)\s*=>\s*(.*)$', line.strip())
        if not m:
            continue
        cmd = m.group(1)
        resp = m.group(2).strip()
        data = ''
        sw = ''
        if resp.startswith('(no data)'):
            sw = resp[len('(no data)'):].strip().replace(' ', '')
        else:
            parts = resp.split()
            sw = parts[-1] if parts else ''
            data = ''.join(parts[:-1])
        exchanges.append((cmd + data + sw).lower())
    return exchanges


def parse_pcap(path):
    """Return (apdu_list, atr_count) where apdu_list is list of (apdu_hex, flags)
    tuples for APDU (sub_type 0) packets, and atr_count is the number of ATR
    (sub_type 1) packets."""
    data = open(path, 'rb').read()
    off = 24
    out = []
    atr_count = 0
    while off < len(data):
        if off + 16 > len(data):
            break
        ts_s, ts_u, caplen, origlen = struct.unpack('<IIII', data[off:off + 16])
        if off + 16 + caplen > len(data):
            break
        pkt = data[off + 16:off + 16 + caplen]
        off += 16 + caplen
        if caplen < 58:
            continue
        glen = struct.unpack('>H', pkt[38:40])[0]
        g = pkt[42:42 + glen - 8]
        if g[12] == 0:  # APDU
            flags = g[15]  # GSMTAP_FLAG_BAD_FCS etc.
            out.append((g[16:].hex(), flags))
        elif g[12] == 1:  # ATR
            atr_count += 1
    return out, atr_count


def is_cat(apdu_hex):
    b = bytes.fromhex(apdu_hex)
    if len(b) < 2:
        return False
    return b[0] == 0x80 and b[1] in CAT_INS


def looks_valid(apdu_hex):
    """Structural validation for an ISO 7816-4 T=0 APDU.

    Delegates to validate_t0_apdu(); kept as a thin wrapper for
    backwards compatibility with existing reports."""
    b = bytes.fromhex(apdu_hex)
    valid, _ = validate_t0_apdu(b)
    return valid


def byte_diff_details(expected_hex, actual_hex):
    """Return list of (offset, expected_byte, actual_byte) for mismatched bytes."""
    eb = bytes.fromhex(expected_hex)
    ab = bytes.fromhex(actual_hex)
    diffs = []
    for i in range(min(len(eb), len(ab))):
        if eb[i] != ab[i]:
            diffs.append((i, eb[i], ab[i]))
    for i in range(len(eb), len(ab)):
        diffs.append((i, None, ab[i]))
    for i in range(len(ab), len(eb)):
        diffs.append((i, eb[i], None))
    return diffs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('reader_log', nargs='?', default=None,
                    help='PC/SC reader log')
    ap.add_argument('pcap', nargs='?', default=None,
                    help='Decoded GSMTAP pcap')
    ap.add_argument('--pcap-only', action='store_true',
                    help='Analyze pcap without a reader log (phone traces)')
    args = ap.parse_args()

    if args.pcap_only:
        reader = []
        if args.pcap is None:
            # --pcap-only pcap  (pcap is the first positional)
            if args.reader_log:
                pcap_path = args.reader_log
            else:
                ap.error('--pcap-only requires a pcap argument')
        else:
            pcap_path = args.pcap
    else:
        if args.reader_log is None or args.pcap is None:
            ap.error('requires reader_log and pcap, or --pcap-only pcap')
        reader = parse_reader_log(args.reader_log)
        pcap_path = args.pcap

    pcap_raw, atr_count = parse_pcap(pcap_path)
    pcap = [h for h, _ in pcap_raw]
    pcap_flags = [f for _, f in pcap_raw]

    sm = difflib.SequenceMatcher(None, reader, pcap, autojunk=False)
    matched = sm.get_matching_blocks()
    matched = [m for m in matched if m.size > 0]

    matched_reader = set()
    matched_pcap = set()
    for a, b, size in matched:
        for k in range(size):
            matched_reader.add(a + k)
            matched_pcap.add(b + k)

    reader_missed = [i for i in range(len(reader)) if i not in matched_reader]
    pcap_unmatched = [i for i in range(len(pcap)) if i not in matched_pcap]
    pcap_cat = [i for i in pcap_unmatched if is_cat(pcap[i])]
    pcap_dup = [i for i in pcap_unmatched
                if i not in pcap_cat and looks_valid(pcap[i])]
    pcap_garbage = [i for i in pcap_unmatched
                    if i not in pcap_cat and i not in pcap_dup]

    # --- Degradation metrics ---

    # BAD_FCS: decoder-flagged desynced APDUs
    bad_fcs_indices = [i for i in range(len(pcap))
                       if pcap_flags[i] & GSMTAP_FLAG_BAD_FCS]
    bad_fcs_in_garbage = [i for i in bad_fcs_indices if i in pcap_garbage]
    bad_fcs_in_dup = [i for i in bad_fcs_indices if i in pcap_dup]
    bad_fcs_in_cat = [i for i in bad_fcs_indices if i in pcap_cat]
    bad_fcs_in_matched = [i for i in bad_fcs_indices if i in matched_pcap]

    # CONCAT: structurally valid packets that embed complete exchanges
    # (a byte-drop mis-frame swallowed several real exchanges in one).
    concat_indices = [i for i in range(len(pcap))
                      if embedded_exchanges(bytes.fromhex(pcap[i]))]

    # Payload mismatches: LCS-matched pairs where bytes differ
    payload_mismatches = []
    for a, b, size in matched:
        for k in range(size):
            ri, pi = a + k, b + k
            if reader[ri] != pcap[pi]:
                payload_mismatches.append((ri, pi, reader[ri], pcap[pi]))

    # Suspicious CLA: check all capture APDUs
    suspicious_cla = []
    for i, hex_str in enumerate(pcap):
        b = bytes.fromhex(hex_str)
        if len(b) < 1:
            continue
        cla = b[0]
        if cla == 0x80:
            continue
        if cla not in VALID_CLA:
            suspicious_cla.append((i, hex_str))

    # --- Report ---

    print('reader exchanges         : %d' % len(reader))
    print('capture ATRs             : %d' % atr_count)
    print('capture APDUs            : %d' % len(pcap))
    print('byte-exact matches (LCS) : %d' % len(matched_reader))
    print('reader exchanges not in capture (pre-capture / dropped): %d'
          % len(reader_missed))
    print('capture APDUs not in reader log:')
    print('  - proactive/CAT (unlogged by reader SDK): %d' % len(pcap_cat))
    print('  - valid exchanges (reader retries/dupes): %d' % len(pcap_dup))
    print('  - GARBAGE (mis-framed/desync): %d' % len(pcap_garbage))
    for i in pcap_garbage[:15]:
        print('      GARBAGE: %s' % pcap[i])

    print('')
    print('Degradation metrics:')
    print('  - BAD_FCS (desynced by decoder): %d' % len(bad_fcs_indices))
    if bad_fcs_indices:
        print('    in GARBAGE: %d, in retries: %d, in CAT: %d, in matched: %d'
              % (len(bad_fcs_in_garbage), len(bad_fcs_in_dup),
                 len(bad_fcs_in_cat), len(bad_fcs_in_matched)))
    print('  - CONCAT (multi-exchange swallowed in one packet): %d'
          % len(concat_indices))
    for i in concat_indices[:10]:
        print('      pcap[%d]: %s' % (i, pcap[i][:72]))
    print('  - payload mismatches (LCS-matched, bytes differ): %d'
          % len(payload_mismatches))
    for ri, pi, exp, act in payload_mismatches[:10]:
        diffs = byte_diff_details(exp, act)
        diff_str = ', '.join(
            'off%+d: %02x->%02x' % (o, e if e is not None else 0xff,
                                     a if a is not None else 0xff)
            for o, e, a in diffs[:5])
        print('      reader[%d] vs pcap[%d]: %s' % (ri, pi, diff_str))
    if len(payload_mismatches) > 10:
        print('      ... and %d more' % (len(payload_mismatches) - 10))
    print('  - suspicious CLA: %d' % len(suspicious_cla))
    for i, hex_str in suspicious_cla[:10]:
        b = bytes.fromhex(hex_str)
        print('      pcap[%d]: CLA=0x%02x  %s' % (i, b[0], hex_str[:40]))
    if len(suspicious_cla) > 10:
        print('      ... and %d more' % (len(suspicious_cla) - 10))

    # A pcap with zero APDUs while the reader log has exchanges is a
    # vacuous pass: the decoder produced nothing to validate.  Flag it.
    no_apdu_failure = (len(pcap) == 0 and len(reader) > 0)
    if no_apdu_failure:
        print('\nWARNING: capture contains 0 APDUs but reader log has %d exchange(s).'
              % len(reader))

    ok = (len(pcap_garbage) == 0
          and len(concat_indices) == 0
          and len(payload_mismatches) == 0
          and len(suspicious_cla) == 0
          and not no_apdu_failure)
    if ok:
        print('\nRESULT: OK - capture fully explained (reader + CAT + valid retries)')
    else:
        problems = []
        if pcap_garbage:
            problems.append('%d garbage APDU(s)' % len(pcap_garbage))
        if concat_indices:
            problems.append('%d CONCAT packet(s)' % len(concat_indices))
        if payload_mismatches:
            problems.append('%d payload mismatch(es)' % len(payload_mismatches))
        if suspicious_cla:
            problems.append('%d suspicious CLA' % len(suspicious_cla))
        if no_apdu_failure:
            problems.append('0 capture APDUs')
        print('\nRESULT: UNCLEAN - %s' % ', '.join(problems))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
