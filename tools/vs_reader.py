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

Usage:
  python3 tools/vs_reader.py <reader.log> <capture.pcap>
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
    """Return list of APDU (sub_type 0) payload hex strings, in order."""
    data = open(path, 'rb').read()
    off = 24
    out = []
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
            out.append(g[16:].hex())
    return out


def is_cat(apdu_hex):
    b = bytes.fromhex(apdu_hex)
    if len(b) < 2:
        return False
    return b[0] == 0x80 and b[1] in CAT_INS


def looks_valid(apdu_hex):
    """Heuristic: a plausible ISO 7816-4 exchange has a sane CLA (not the
    T=0 NULL byte 0x60), is >= 7 bytes, and ends in a status word
    (SW1 in 0x6x or 0x9x)."""
    b = bytes.fromhex(apdu_hex)
    if len(b) < 7:
        return False
    if b[0] == 0x60:  # NULL byte mis-framed as CLA
        return False
    sw1 = b[-2]
    return (0x60 <= sw1 <= 0x6F) or (0x90 <= sw1 <= 0x9F)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('reader_log')
    ap.add_argument('pcap')
    args = ap.parse_args()

    reader = parse_reader_log(args.reader_log)
    pcap = parse_pcap(args.pcap)

    sm = difflib.SequenceMatcher(None, reader, pcap, autojunk=False)
    matched = sm.get_matching_blocks()
    # last block is the sentinel (i==j==0)
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

    print('reader exchanges         : %d' % len(reader))
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

    # success = every capture APDU is either a matched reader exchange, a
    # recognized CAT exchange, or a structurally valid exchange (a retry
    # the reader SDK consolidated).  Anything else is mis-framing.
    ok = (len(pcap_garbage) == 0)
    print('\nRESULT: %s' % ('OK - capture fully explained (reader + CAT + valid retries)'
                            if ok else
                            'UNCLEAN - %d mis-framed capture APDU(s)' % len(pcap_garbage)))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
