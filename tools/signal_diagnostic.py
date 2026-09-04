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

import numpy as np


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


def read_sr_all(path):
    """Read all logic samples into a numpy uint8 array."""
    with zipfile.ZipFile(path, 'r') as zf:
        chunk_names = [n for n in zf.namelist() if n.startswith('logic-1-')]
        chunk_names.sort(key=lambda n: int(n.split('-')[-1]))
        chunks = [zf.read(c) for c in chunk_names]
    return np.frombuffer(b''.join(chunks), dtype=np.uint8)


def get_channel_bit(metadata, channel_name):
    """Return the bit position (0-indexed) for a channel name, or None."""
    for probe_num, name in metadata['probes'].items():
        if name == channel_name:
            return probe_num - 1  # probe 1 = bit 0, probe 2 = bit 1, ...
    return None


# ---------------------------------------------------------------------------
# Signal measurement helpers
# ---------------------------------------------------------------------------

def extract_bit(arr, bit):
    """Extract a single bit from a numpy uint8 array -> bool array."""
    return (arr >> bit) & 1


def measure_clk_fast(clk_arr, sr):
    """Measure CLK frequency from rising edges using numpy."""
    if len(clk_arr) == 0:
        return {'ok': False, 'reason': 'no data'}

    # Find rising edges: 0->1 transitions
    diffs = np.diff(clk_arr.astype(np.int8))
    rising = np.where(diffs == 1)[0] + 1  # +1 because diff shifts by 1

    if len(rising) < 2:
        return {
            'ok': False,
            'reason': f'only {len(rising)} rising edges (need >= 2)',
            'transitions': len(rising),
        }

    spacings = np.diff(rising)
    median_spc = float(np.median(spacings))
    freq = sr / median_spc if median_spc > 0 else 0

    duration_s = (rising[-1] - rising[0]) / sr

    # Frequency change: compare first and last quarter
    freq_change = None
    if len(spacings) >= 20:
        n = len(spacings)
        q1 = float(np.median(spacings[:n // 4]))
        q4 = float(np.median(spacings[3 * n // 4:]))
        if q1 > 0 and q4 > 0:
            f1 = sr / q1
            f4 = sr / q4
            change_pct = abs(f1 - f4) / max(f1, f4) * 100
            if change_pct > 10:
                freq_change = f'{change_pct:.0f}% change ({f1/1e6:.2f} -> {f4/1e6:.2f} MHz)'

    return {
        'ok': True,
        'rising_edges': len(rising),
        'frequency_mhz': freq / 1e6,
        'median_period_samples': median_spc,
        'duration_ms': duration_s * 1000,
        'freq_change': freq_change,
    }


def count_transitions(arr):
    """Count transitions in a numpy bool array."""
    if len(arr) == 0:
        return 0
    return int(np.sum(np.diff(arr.astype(np.int8)) != 0))


def measure_data_fast(data_arr, clk_arr, sr):
    """Measure DATA signal using numpy."""
    if len(data_arr) == 0:
        return {'ok': False, 'reason': 'no data'}

    transitions = count_transitions(data_arr)

    clk_data_corr = None
    if len(clk_arr) == len(data_arr) and len(clk_arr) > 1:
        clk_diffs = np.diff(clk_arr.astype(np.int8))
        data_diffs = np.diff(data_arr.astype(np.int8))
        clk_edges = np.where(clk_diffs == 1)[0]
        if len(clk_edges) > 0:
            matching = int(np.sum(data_diffs[clk_edges] != 0))
            clk_data_corr = f'{matching}/{len(clk_edges)} ({matching / len(clk_edges) * 100:.0f}%)'

    return {
        'ok': True,
        'transitions': transitions,
        'clk_data_correlation': clk_data_corr,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_analysis(path, clk_name, data_name, rst_name, vcc_name):
    """Run full signal analysis on a .sr file. Returns results dict."""
    meta = parse_sr_metadata(path)
    sr = meta['samplerate']

    clk_bit = get_channel_bit(meta, clk_name)
    data_bit = get_channel_bit(meta, data_name)
    rst_bit = get_channel_bit(meta, rst_name)
    vcc_bit = get_channel_bit(meta, vcc_name)

    raw = read_sr_all(path)
    total_samples = len(raw)
    duration_s = total_samples / sr

    # Find first CLK activity
    first_clk_sample = None
    if clk_bit is not None:
        clk_arr = extract_bit(raw, clk_bit)
        clk_edges = np.where(np.diff(clk_arr.astype(np.int8)) == 1)[0]
        if len(clk_edges) > 0:
            first_clk_sample = int(clk_edges[0])

    results = {
        'samplerate_mhz': sr / 1e6,
        'total_samples': total_samples,
        'duration_ms': duration_s * 1000,
        'channels_found': {
            'CLK': clk_name if clk_bit is not None else None,
            'DATA': data_name if data_bit is not None else None,
            'RST': rst_name if rst_bit is not None else None,
            'VCC': vcc_name if vcc_bit is not None else None,
        },
        'first_activity_sample': first_clk_sample or 0,
    }

    # CLK
    if clk_bit is not None:
        results['CLK'] = measure_clk_fast(extract_bit(raw, clk_bit), sr)
    else:
        results['CLK'] = {'ok': False, 'reason': f'channel "{clk_name}" not found'}

    # RST
    if rst_bit is not None:
        rst_arr = extract_bit(raw, rst_bit)
        rst_t = count_transitions(rst_arr)
        results['RST'] = {
            'ok': True, 'transitions': rst_t,
            'stable_pct': (1 - rst_t / max(total_samples, 1)) * 100,
            'noisy': rst_t > total_samples * 0.01,
        }
    else:
        results['RST'] = {'ok': False, 'reason': f'channel "{rst_name}" not found'}

    # VCC
    if vcc_bit is not None:
        vcc_arr = extract_bit(raw, vcc_bit)
        vcc_t = count_transitions(vcc_arr)
        results['VCC'] = {
            'ok': True, 'transitions': vcc_t,
            'stable_pct': (1 - vcc_t / max(total_samples, 1)) * 100,
            'noisy': vcc_t > total_samples * 0.01,
        }
    else:
        results['VCC'] = {'ok': False, 'reason': f'channel "{vcc_name}" not found'}

    # DATA
    if data_bit is not None:
        data_arr = extract_bit(raw, data_bit)
        clk_arr = extract_bit(raw, clk_bit) if clk_bit is not None else np.array([], dtype=np.uint8)
        results['DATA'] = measure_data_fast(data_arr, clk_arr, sr)
    else:
        results['DATA'] = {'ok': False, 'reason': f'channel "{data_name}" not found'}

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
