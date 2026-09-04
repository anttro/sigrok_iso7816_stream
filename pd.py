##
## Copyright (C) 2020 Sven Soltermann <sven@handyman.ch>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
import struct
import sys
import codecs
import ctypes
import traceback
from collections import deque

from .gsmtap_stream import (GsmtapStreamSender,
    GSMTAP_SIM_APDU, GSMTAP_SIM_ATR, GSMTAP_SIM_PPS,
    GSMTAP_SIM_RST_EVENT, GSMTAP_SIM_VCC_EVENT,
    GSMTAP_FLAG_BAD_FCS)

VERSION = '1.1.4'



class Ann:
    '''Annotation and binary output classes.'''
    (
        ANN_WARN, ANN_BYTE, ANN_ATR, ANN_PPS, ANN_T0, ANN_T1, ANN_T1IBLOCK, ANN_T1RBLOCK, ANN_T1SBLOCK, ANN_APDU,
        ANN_RST, ANN_VCC,
    ) = range(12)


class pcap_udp_pkt():
    # GSM TAP
    h  = b''

    # layer_2
    h += b'\x00\x00\x00\x00\x00\x00' # destination_mac
    h += b'\x00\x00\x00\x00\x00\x00' # source_mac
    h += b'\x08\x00' # layer_3_protocol

    # layer_3
    h += b'\x45' # version
    h += b'\x00' # DiffServField
    h += b'\xFF\xFF' # total_length
    h += b'\x2B\x0D' # Identification
    h += b'\x40\x00' # Flags
    h += b'\x40' # TTL
    h += b'\x11' # layer_4_protocol
    h += b'\x00\x00' # header_checksum
    h += b'\x7F\x00\x00\x01' # source_ip
    h += b'\x7F\x00\x00\x01' # dest_ip
    
    # layer_4
    h += b'\xcc\x46' # source_port
    h += b'\x12\x79' # dest_port
    h += b'\x00\x00' # datagram_length
    h += b'\x00\x00' # checksum

    def __init__(self, ts, data, sub_type=GSMTAP_SIM_APDU, flags=0):
        self.header = bytearray(pcap_udp_pkt.h)
        self.data = b''
        self.set_timestamp(ts)
        self.set_data(data, sub_type, flags)

    def set_timestamp(self, ts):
        self.timestamp = ts

    def set_data(self, data, sub_type=GSMTAP_SIM_APDU, flags=0):
        gsmtap = bytearray(b'\x02\x04\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        gsmtap[12] = sub_type
        gsmtap[15] = flags
        self.data = list(gsmtap + bytes(data));
        self.header[16:18] = struct.pack('>H', len(self.data) + 28)
        self.header[38:40] = struct.pack('>H', len(self.data) + 8)

    def packet(self):
        return bytes(self.header) + bytes(self.data)

    def record_header(self):
        # See https://wiki.wireshark.org/Development/LibpcapFileFormat.
        (secs, usecs) = self.timestamp
        h  = struct.pack('<I', secs) # TS seconds
        h += struct.pack('<I', usecs) # TS microseconds
        # No truncation, so both lengths are the same.
        h += struct.pack('<I', len(self)) # Captured len
        h += struct.pack('<I', len(self)) # Original len
        return h

    def __len__(self):
        return len(self.h) + len(self.data)

def plausible_sw(sw1):
    '''T=0 status word first byte sanity check.  SW1 is 0x9x (normal
    processing) or 0x6x (warning/error classes).  Anything else means
    the byte stream was almost certainly mis-framed.'''
    return (0x60 <= sw1 <= 0x6F) or (0x90 <= sw1 <= 0x9F)


def plausible_cla(cla):
    '''Check if CLA byte is a recognized ISO 7816 class.

    Valid CLA values per ISO 7816-4 / 3GPP TS 102 221 / TS 51.011:
      0x00 - Basic interindustry
      0x04 - Basic + secure messaging
      0x08 - USIM (3GPP)
      0x80 - USIM/CAT (3GPP)
      0x84 - USIM secure messaging
      0xA0 - SIM/GSM (TS 51.011)
      0xB0 - SIM/GSM extended

    Non-standard CLA values indicate the decoder likely mis-framed the
    byte stream and should attempt to resync.'''
    return cla in (0x00, 0x04, 0x08, 0x80, 0x84, 0xA0, 0xB0)


def plausible_ins(ins):
    '''Check if INS byte is a structurally valid T=0 instruction.

    Per ISO 7816-4 §12.1.1 / TS 102 221:
      - 0x00 is reserved/invalid.
      - MSB nibble 0x6/0x9 collides with status words.
      - LSB must be 0 (standard interindustry commands).

    Used together with plausible_cla() to distinguish a real command header
    from noise while hunting for an ATR.'''
    if ins == 0x00:
        return False
    if (ins & 0xF0) == 0x60 or (ins & 0xF0) == 0x90:
        return False
    if (ins & 0x01) != 0:
        return False
    return True


def is_desynced(packet):
    '''Classify an emitted T=0 packet as mis-framed.

    All-zero packets are idle-low noise (suppressed elsewhere), NOT
    desync.  A real TPDU must reach its status word: >= 7 bytes ending
    in a plausible SW1, never exceed the T=0 maximum, and start with a
    valid CLA byte.'''
    if not packet:
        return False
    if all(b == 0 for b in packet):
        return False
    return (len(packet) > MAX_TPDU_LEN
            or len(packet) < 7
            or not plausible_sw(packet[-2])
            or not plausible_cla(packet[0]))


MAX_TPDU_LEN = 271  # ISO 7816-3 T=0: header(5) + proc + 255 + SW(2) < 271
IDLE_RESYNC_ETU = 4  # idle bit-periods marking an exchange boundary
MAX_RESYNC_ATTEMPTS = 1024  # bail out if no idle gap found in that many tries


class Decoder(srd.Decoder):
    api_version = 3
    id = 'iso7816'
    name = 'ISO 7816'
    longname = 'Smartcard'
    desc = 'ISO 7816 decoder (smartcard)'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['iso7816']
    tags = ['Embedded/industrial']
    channels = (
        {'id': 'clk', 'name': 'CLK', 'desc': 'clock'},
        {'id': 'data', 'name': 'data', 'desc': 'data'},
    )
    optional_channels = (
        {'id': 'rst', 'name': 'RST', 'desc': 'reset (enable via rst_detect=true)'},
        {'id': 'vcc', 'name': 'VCC', 'desc': 'power supply, digital only (enable via vcc_detect=true)'},
    )
    options = (
        {'id': 'clock_option', 'desc': 'Clock option',
            'default': 'native', 'values': ('native', 'detect', 'sample_as_clock')},
        {'id': 'protocol', 'desc': 'Protocol',
            'default': 'auto', 'values': ('auto', 'T=0', 'T=1')},
        {'id': 'starts_with_atr', 'desc': 'Starts with ATR',
            'default': 'false', 'values': ('true', 'false')},
        {'id': 'gsmtap_enable', 'desc': 'Live GSMTAP UDP stream (simtrace2-sniff compatible)',
            'default': 'true', 'values': ('true', 'false')},
        {'id': 'gsmtap_host', 'desc': 'GSMTAP destination host', 'default': '127.0.0.1'},
        {'id': 'gsmtap_port', 'desc': 'GSMTAP destination port', 'default': 4729},
        {'id': 'pcap_file', 'desc': 'Write PCAP to file in addition to binary output', 'default': ''},
        {'id': 'rst_detect', 'desc': 'Track RST pin events (needs rst channel assigned)',
            'default': 'false', 'values': ('false', 'true')},
        {'id': 'vcc_detect', 'desc': 'Track VCC pin events (needs vcc channel assigned)',
            'default': 'false', 'values': ('false', 'true')},
    )
    annotations = (
        ('warning', 'Human-readable warnings'),
        ('byte', 'Byte'),
        ('atr', 'ATR (Answer to Reset)'),
        ('pps', 'PPS (Protocol and parameters selection)'),
        ('t0', 'T=0 packet'),
        ('t1', 'T=1 packet'),
        ('t1-iblock', 'T=1 I-Block'),
        ('t1-rblock', 'T=1 R-Block'),
        ('t1-sblock', 'T=1 S-Block'),
        ('apdu', 'APDU'),
        ('rst', 'RST event'),
        ('vcc', 'VCC event'),
    )
    annotation_rows = (
        ('warnings', 'Warnings', (Ann.ANN_WARN,)),
        ('bytes', 'Bytes', (Ann.ANN_BYTE,)),
        ('type', 'Type', (Ann.ANN_ATR,Ann.ANN_PPS,Ann.ANN_T0,Ann.ANN_T1)),
        ('t1blocks', 'T=1 Decode', (Ann.ANN_T1IBLOCK,Ann.ANN_T1RBLOCK,Ann.ANN_T1SBLOCK)),
        ('apdus', 'apdu', (Ann.ANN_APDU,)),
        ('lines', 'Lines', (Ann.ANN_RST, Ann.ANN_VCC)),
    )
    binary = (
        ('pcap', 'PCAP format'),
    )

    clock_rate = {
        0: 372,
        1: 372,
        2: 558,
        3: 744,
        4: 1116,
        5: 1488,
        6: 1860,
        9: 512,
        10: 768,
        11: 1024,
        12: 1536,
        13: 2048
    }
    baud_rate = {
        0: 1,
        1: 1,
        2: 2,
        3: 4,
        4: 8,
        5: 16,
        6: 32,
        7: 64,
        8: 12,
        9: 20
    }


    # Channel indices within the pins tuple returned by self.wait()
    # (declaration order of self.channels).
    CLK_IDX = 0
    DATA_IDX = 1
    RST_IDX = 2
    VCC_IDX = 3

    def __init__(self):
        self.reset()

    def log(self, *args):
        print(args, file=sys.stderr, flush=True)

    def reset(self):
        self.peeked_byte = None
        self.peeked_samplenum = -1
        # Replay buffer for bytes read ahead but not consumed (used by the
        # command-detect path in the ATR hunt to hand a command header back
        # to the DATA state without dropping it).
        self._replay = deque()
        self.wrote_pcap_header = False
        self.samplerate = None
        self.sample_as_clock = False
        self.detect_clock = False
        self.fi = self.clock_rate[0]
        self.di = self.baud_rate[0]
        self.ss = self.es = -1
        self.state = 'FIND START'
        self.bits = []
        self.clock_skip = 372
        # Measured bit period (samples or CLK edges) from the first frame;
        # 372 = spec default until measured.  Must exist before any PPS
        # handling -- native mode never measures it explicitly.
        self.detected_clock_skip = 372
        self.bit_samples = None
        self._etu_confirm_count = 0
        self._etu_fail_count = 0
        self._edge_spacings = deque(maxlen=128)
        self._samples_per_clock = None
        # True when clock_skip is known to be correct: after a parsed ATR
        # (372 default), an accepted PPS (FI/DI), or a successful ETU-based
        # recovery on a mid-session capture.  The CLK-sync reader is only
        # trusted when this is set; otherwise the edge-list reader (which
        # uses bit_samples) is the safe fallback.
        self._clock_skip_confident = False
        self._start_fall = None
        self._edge_read = True
        self._last_sn = -1
        self._eof = False
        self._prev_wait_sn = None
        self._stall = 0
        self.lastSamplePositive = True
        self.sampleOverflowCount = 0
        # Rolling parity-error monitor: warns when the wire degrades
        # (e.g. GSM TX bursts coupling into the probe wiring).
        self.parity_hist = deque(maxlen=64)
        self.sig_warned = False
        # Stuck-line watchdog: consecutive all-zero frames usually mean
        # the I/O probe lost contact (floating low), not data.
        self.zero_run = 0
        # Idle-low APDU suppression counter (all-zero T=0 reads).
        self._idle_low = 0
        # Set after a desync so the next DATA step re-aligns on an
        # inter-frame idle gap before resuming.
        self._resync = False
        # Set by handle_pps() when an accepted PPS changes the bit rate.
        # Forces _measure_etu() on the next decode_step() cycle so the
        # decoder re-locks to the new ETU from the live DATA line.
        self._pps_speed_changed = False
        # Count of times the ATR hunt failed to find a valid TS byte --
        # bounds the "keep hunting" loop so a mid-session sniffer (no ATR
        # ever present) eventually falls back to T=0 parsing instead of
        # looping forever.
        self._atr_hunt_count = 0
        # PPS is only attempted once after an ATR/warm reset.  Prevents
        # idle-line 0xFF bytes from being parsed as an endless stream of
        # PPS requests when the card does not actually perform PPS.
        self._pps_attempted = False
        self.gsmtap = None
        self.pcap_fh = None
        self.track_rst = False
        self.track_vcc = False
        # RST/VCC line tracking uses level-stability hysteresis (see
        # _line_hyst): a level must stay continuously stable for
        # vcc_min_gap samples before it is "confirmed" and reported.  This
        # makes power-up and power-down symmetric -- a VCC sense line that
        # rings on the rising edge (noisy/floating tap) no longer loses its
        # "VCC on" event; it simply fires once the line settles HIGH.
        # last_rst/last_vcc hold the *confirmed* level; *_cand / *_cand_sn
        # track a pending level and the sample it first appeared.
        self.last_rst = 0
        self.last_vcc = 0
        self.rst_cand = None
        self.rst_cand_sn = 0
        self.vcc_cand = None
        self.vcc_cand_sn = 0
        # Minimum quiet window (samples) a NEW level must hold before it is
        # honored.  10 ms @ 16 MHz; set from samplerate in metadata().
        self.vcc_min_gap = 0            # 0 = hysteresis disabled (no samplerate)

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value
            if self.samplerate:
                self.secs_per_sample = float(1) / float(self.samplerate)
                # 10 ms debounce window, scaled to samples.
                self.vcc_min_gap = int(self.samplerate * 0.010)

    def start(self):
        self.log("iso7816 decoder v{}".format(VERSION))
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_binary = self.register(srd.OUTPUT_BINARY)
        self.sample_as_clock = self.options['clock_option'] == "sample_as_clock"
        self.detect_clock = self.options['clock_option'] == "detect"
        self.starts_with_atr = self.options['starts_with_atr'] == "true"
        if self.starts_with_atr:
            self.state = 'FIND START'
        else:
            self.state = 'DATA'
        self._atr_parsed = False
        # Inverse convention (TS=0x3F): logic 1 = LOW, logic 0 = HIGH.
        # Set when TS=0x3F is detected; all subsequent byte reads invert bits.
        self._inverse_convention = False
        # For an ATR-included capture the ATR is sent at the default 372 CLK
        # cycles/bit, so clock_skip=372 is known-correct from the start.  For
        # a mid-session capture we do not know whether the card already PPS'd
        # to a faster ETU, so clock_skip is not trusted until recovered.
        self._clock_skip_confident = self.starts_with_atr
        if (self.options['protocol'] == "T=0"):
            self.hasT0 = True
            self.hasT1 = False
        elif (self.options['protocol'] == "T=1"):
            self.hasT0 = False
            self.hasT1 = True
        else:
            self.hasT0 = False
            self.hasT1 = False
        # True only when the user explicitly set protocol=T=0/T=1 (not 'auto').
        # Used to enable mid-session raw-burst emission (below) without
        # affecting the default auto-protocol path.
        self.explicit_protocol = self.options['protocol'] in ("T=0", "T=1")

        # Live GSMTAP UDP stream (default on, mimics simtrace2-sniff).
        if (self.options['gsmtap_enable'] == "true" and self.options['gsmtap_host']):
            try:
                self.gsmtap = GsmtapStreamSender(self.options['gsmtap_host'],
                                                 int(self.options['gsmtap_port']))
                self.log("GSMTAP stream to",
                         "%s:%s" % (self.options['gsmtap_host'], self.options['gsmtap_port']))
            except OSError as e:
                self.gsmtap = None
                self.log("GSMTAP stream disabled:", str(e))

        # Optional direct PCAP file output.
        if (self.options['pcap_file']):
            try:
                self.pcap_fh = open(self.options['pcap_file'], 'wb')
                self.pcap_fh.write(self.pcap_global_header())
            except OSError as e:
                self.pcap_fh = None
                self.log("PCAP file disabled:", str(e))

        # Optional RST/VCC line tracking.
        self.track_rst = self.options['rst_detect'] == "true"
        self.track_vcc = self.options['vcc_detect'] == "true"
        if (self.track_rst and hasattr(self, 'has_channel')
                and not self.has_channel(self.RST_IDX)):
            self.log("rst_detect=true but 'rst' channel not assigned - disabled")
            self.track_rst = False
        if (self.track_vcc and hasattr(self, 'has_channel')
                and not self.has_channel(self.VCC_IDX)):
            self.log("vcc_detect=true but 'vcc' channel not assigned - disabled")
            self.track_vcc = False

    def finish(self):
        if self.pcap_fh is not None:
            try:
                self.pcap_fh.close()
            except OSError:
                pass
            self.pcap_fh = None
        if self.gsmtap is not None:
            self.gsmtap.close()
            self.gsmtap = None

    def emit_packet(self, sub_type, payload, ss, es, flags=0):
        '''Emit one event as PCAP binary stream + PCAP file + GSMTAP UDP.

        `flags` is written into the GSMTAP header `res` byte (see
        GSMTAP_FLAG_BAD_FCS in gsmtap_stream).'''
        ts = self.ts_from_samplenum(ss)
        pkt = pcap_udp_pkt(ts, payload, sub_type, flags)
        self.put(ss, es, self.out_binary, [0, pkt.record_header()])
        self.put(ss, es, self.out_binary, [0, pkt.packet()])
        if self.pcap_fh is not None:
            self.pcap_fh.write(pkt.record_header())
            self.pcap_fh.write(pkt.packet())
        if self.gsmtap is not None:
            self.gsmtap.send(sub_type, payload, flags)

    def _line_hyst(self, lvl, confirmed, cand, cand_sn):
        '''Level-stability hysteresis for RST/VCC line tracking.

        A level different from `confirmed` becomes a *candidate*.  It is
        confirmed (and returned for emission) once it has been
        continuously stable for >= vcc_min_gap samples -- either because it
        persists that long, or because it ends (the line moves again) after
        having been stable that long.  This matters because the decoder is
        edge-driven: the stable window between a fall and the next rise is
        never re-sampled, so a candidate must be confirmable when it ENDS.

        Returns (emit_lvl, edge_sn, new_confirmed, new_cand, new_cand_sn):
        emit_lvl is the level just confirmed (or None); edge_sn is the sample
        the (now confirmed) level first appeared.'''
        now = self.samplenum
        if lvl == confirmed:
            # Candidate (if any) ended by returning to the confirmed level.
            # If it had been stable long enough, report it; the current line
            # level (lvl) is now the state to track as a fresh candidate, so
            # a genuine rise (e.g. power-up) is not lost on the same call.
            if cand is not None and ((not self.vcc_min_gap)
                                     or (now - cand_sn) >= self.vcc_min_gap):
                return (cand, cand_sn, cand, lvl, now)
            return (None, 0, confirmed, None, 0)
        if cand is None:
            # First divergence from confirmed.
            if not self.vcc_min_gap:
                # Hysteresis disabled: report the edge immediately.
                return (lvl, now, lvl, None, 0)
            return (None, 0, confirmed, lvl, now)
        if cand == lvl:
            # Same candidate persists: confirm once stable long enough.
            if (not self.vcc_min_gap) or (now - cand_sn) >= self.vcc_min_gap:
                return (lvl, cand_sn, lvl, None, 0)
            return (None, 0, confirmed, cand, cand_sn)
        # lvl differs from both confirmed and the current candidate: the
        # candidate just ended and a new level appeared.  If the candidate
        # was stable, report it; then start tracking the new level.
        if (not self.vcc_min_gap) or (now - cand_sn) >= self.vcc_min_gap:
            return (cand, cand_sn, cand, lvl, now)
        return (None, 0, confirmed, lvl, now)

    def line_events(self, pins):
        '''Check RST/VCC levels via level-stability hysteresis and emit
        events + annotations for confirmed level changes.

        An edge is only reported once the new level has been continuously
        stable for >= vcc_min_gap samples, so a noisy/floating sense line
        that rings on a transition no longer drops the event.  Returns True
        if any event fired.'''
        fired = False
        if (self.track_rst):
            lvl = pins[self.RST_IDX]
            emit_lvl, edge_sn, self.last_rst, self.rst_cand, self.rst_cand_sn = \
                self._line_hyst(lvl, self.last_rst, self.rst_cand, self.rst_cand_sn)
            if emit_lvl is not None:
                direction = 1 if emit_lvl == 0 else 0  # 1=asserted, 0=deasserted
                self.emit_packet(GSMTAP_SIM_RST_EVENT,
                                 bytes([direction, emit_lvl, 0]), edge_sn, edge_sn)
                text = ('RST asserted' if emit_lvl == 0 else 'RST deasserted')
                self.put(edge_sn, edge_sn, self.out_ann, [Ann.ANN_RST, [text]])
                self.log(text)
                fired = True
                if (emit_lvl == 0):
                    # RST asserted (LOW): card entering reset state.  A reset
                    # makes the card send its ATR at the DEFAULT ETU (372 CLK
                    # cycles/bit), so clock_skip must be restored to 372 --
                    # otherwise a post-PPS clock_skip (e.g. 16) would make the
                    # decoder hunt for the fresh ATR at the wrong rate and
                    # mis-frame every byte.  Prepare for the next ATR by
                    # re-arming the hunt and clearing _atr_parsed so the next
                    # RST deassert will also re-arm (first cycle at startup).
                    self._atr_parsed = False
                    self._inverse_convention = False
                    self.clock_skip = 372
                    self.bit_samples = None
                    self.state = 'FIND START'
                    self._atr_hunt_count = 0
                    self._pps_attempted = False
                if (emit_lvl == 1):
                    # RST deasserted (HIGH): card released from reset and
                    # will send a fresh ATR.  However, the 10ms hysteresis
                    # means this event fires AFTER the ATR has already been
                    # parsed and the decoder entered DATA state.  In that
                    # case, stay in DATA so the terminal's T=0 commands
                    # (which follow the ATR) are decoded.  Only re-arm if
                    # _atr_parsed is False (startup / first cycle, where no
                    # ATR has been parsed yet).
                    if self._atr_parsed:
                        self.log("warm reset: staying in DATA (ATR already parsed)")
                    else:
                        self.state = 'FIND START'
                        self._atr_hunt_count = 0
                        self._pps_attempted = False
                        self.log("warm reset: re-arming ATR hunt")
        if (self.track_vcc):
            lvl = pins[self.VCC_IDX]
            emit_lvl, edge_sn, self.last_vcc, self.vcc_cand, self.vcc_cand_sn = \
                self._line_hyst(lvl, self.last_vcc, self.vcc_cand, self.vcc_cand_sn)
            if emit_lvl is not None:
                direction = emit_lvl  # 1=power applied, 0=power removed
                self.emit_packet(GSMTAP_SIM_VCC_EVENT,
                                 bytes([direction, emit_lvl, 0]), edge_sn, edge_sn)
                text = ('VCC on' if emit_lvl == 1 else 'VCC off')
                self.put(edge_sn, edge_sn, self.out_ann, [Ann.ANN_VCC, [text]])
                self.log(text)
                fired = True
        return fired

    def pcap_global_header(self):
        # See https://wiki.wireshark.org/Development/LibpcapFileFormat.
        h  = b'\xd4\xc3\xb2\xa1' # Magic, indicate microsecond ts resolution
        h += b'\x02\x00'         # Major version 2
        h += b'\x04\x00'         # Minor version 4
        h += b'\x00\x00\x00\x00' # Correction vs. UTC, seconds
        h += b'\x00\x00\x00\x00' # Timestamp accuracy
        h += b'\xff\xff\x00\x00' # Max packet len
        h += b'\x01\x00\x00\x00' # Link layer
        return h

    def get_bytes(self, bits):
        byte = 0
        for bit in list(reversed(bits)):
            byte = (byte << 1) | bit
        return byte
    
    def write_pcap_header(self):
        if not self.wrote_pcap_header:
            self.put(0, 0, self.out_binary, [0, self.pcap_global_header()])
            self.wrote_pcap_header = True
    
    def ts_from_samplenum(self, sample):
        x = ctypes.c_uint32(sample).value;
        ovrflow = ctypes.c_uint32(int(self.sampleOverflowCount * 0xFFFFFFFF * self.secs_per_sample)).value
        ts = float(x) * self.secs_per_sample + ovrflow
        return (int(ts), int((ts % 1.0) * 1e6))

    def signal_quality(self, err):
        '''Feed one frame's parity result (1 = bad) into the rolling
        monitor; warn once per degradation episode when >= 8 of the last
        64 frames failed parity.'''
        self.parity_hist.append(err)
        if len(self.parity_hist) < 32:
            return
        errs = sum(self.parity_hist)
        if errs >= 8 and not self.sig_warned:
            self.sig_warned = True
            self.log("SIGNAL INTEGRITY WARNING: {}/{} recent frames failed "
                     "parity (noise? RF burst? contact?)".format(
                         errs, len(self.parity_hist)))
            try:
                wss = max(self.ss, 0)
                wes = max(self.es, wss + 1)
                self.put(wss, wes, self.out_ann,
                         [Ann.ANN_WARN, ["noisy signal"]])
            except Exception:
                pass
        elif errs <= 2:
            self.sig_warned = False

    def read_first_byte(self):
        '''Find the first start-bit falling edge and read the first byte with
        the standard re-anchored reader.  (Mid-session ETU recovery is done by
        _measure_etu, called once from the mid-session branch of decode_step
        before the normal T=0/T=1 framing state machine takes over.)'''
        self.wait_data_falling()
        return self.read_byte_no_wait()

    def _measure_clock_period(self):
        '''Measure the period of the native CLK signal in samples.

        For native CLK mode, the actual bit period is
        clock_skip * samples_per_clock.  Measuring it directly removes the
        hard-coded 3× approximation and gives the correct ETU for the ATR and
        for any post-PPS speed.  Returns True if a stable period was found.

        Collects multiple CLK rising-edge spacings and picks the smallest
        recurring one (like _robust_min) so a single glitch does not skew the
        result.'''
        if self.sample_as_clock or self.detect_clock:
            return False
        spacings = []
        last_sn = None
        try:
            # Collect up to 16 consecutive CLK rising-edge spacings.
            for _ in range(16):
                pins = self.wait({self.CLK_IDX: 'r'})
                if pins is None:
                    return False
                sn = self.samplenum
                if last_sn is not None:
                    spacings.append(sn - last_sn)
                last_sn = sn
            if len(spacings) < 3:
                return False
            # Use average period instead of robust_min to handle varying CLK periods
            # (e.g., 4,3,3 alternating pattern).
            period = sum(spacings) / len(spacings)
            if 2 <= period <= 100000:
                self._samples_per_clock = period
                self.log("clock period (samples):", period)
                return True
        except Exception:
            pass
        return False

    def _compute_bit_samples(self):
        '''Return the best available bit-period estimate in samples.

        Uses the measured clock period if available; otherwise falls back to
        the legacy clock_skip * 3 estimate.'''
        if self._samples_per_clock is not None:
            return int(self.clock_skip * self._samples_per_clock)
        return int(self.clock_skip * 3)

    def _derive_clock_skip_from_etu(self):
        '''Derive clock_skip (CLK edges per ETU) from the recovered ETU.

        For a mid-session capture (no ATR) the card may already be PPS'd to a
        fast ETU, so the default clock_skip=372 is wrong.  Once _measure_etu
        has recovered bit_samples (samples per ETU) and _measure_clock_period
        has recovered _samples_per_clock (samples per CLK cycle), clock_skip
        = bit_samples / _samples_per_clock.  Sets _clock_skip_confident on
        success so the CLK-sync reader is used; leaves it clear (edge-list
        fallback) if the CLK period could not be measured.'''
        if self._samples_per_clock and self.bit_samples:
            cs = int(round(float(self.bit_samples) / float(self._samples_per_clock)))
            if cs >= 1:
                if cs != self.clock_skip:
                    self.log("clock_skip recovered from ETU:", cs,
                             "(bit_samples", self.bit_samples,
                             "/ spc", self._samples_per_clock, ")")
                self.clock_skip = cs
                self._clock_skip_confident = True
                return True
        return False

    def _measure_etu(self):
        '''Recover the live bit period (ETU, in samples) from the DATA line for
        a mid-session capture that has no ATR to derive timing from.

        Jumps to each DATA transition (O(edges), immune to Clock Stop Mode)
        and collects edge spacings until an idle gap ends the burst.  The
        shortest *recurring* spacing equals one etu, so this recovers fast /
        non-standard ETUs (e.g. a phone SIM already PPS'd to a short etu) that
        the spec-default 372-clock etu would mis-read by ~20x.

        The result is **locked after 3 successful decodes**: bit_samples is
        set after measurement, then validated by decoding subsequent bytes.
        If 2 consecutive parity errors occur before validation, the
        measurement is discarded and re-measured from the next burst.
        Consumes one burst for the measurement; the normal framing resumes
        on the next start bit (the first exchange may therefore be
        mis-framed -- expected for a mid-session capture).'''
        if self.bit_samples is not None and self._etu_confirm_count >= 3:
            return
        if self._start_fall is None:
            self.wait_data_falling()
        if self._eof or self._start_fall is None:
            return
        e0 = self._start_fall
        self._start_fall = None  # consumed; framing re-waits on its own
        self.ss = e0
        idle_limit = int((self.bit_samples or
                           self._compute_bit_samples()) * 20)
        if idle_limit < 3000:
            idle_limit = 3000
        edges = [(e0, 0)]
        last_sn = e0
        while True:
            pins = self.wait({self.DATA_IDX: 'e'})
            if pins is None:
                break
            sn = self.samplenum
            if sn <= last_sn:
                break  # no progress (end of capture) -> stop scan
            last_sn = sn
            d = pins[self.DATA_IDX]
            if (sn - edges[-1][0]) > idle_limit:
                # Big gap => burst ended; leave this edge for the framing.
                break
            edges.append((sn, d))
        if len(edges) >= 2:
            spacings = [edges[i + 1][0] - edges[i][0]
                        for i in range(len(edges) - 1)]
            # Filter glitches (< MIN_ETU) then check if the first spacing
            # is an outlier (scan started in a noisy pre-burst region).
            MIN_ETU = 12
            valid = [s for s in spacings if s >= MIN_ETU]
            if len(valid) >= 2:
                med = sorted(valid)[len(valid) // 2]
                # If the first valid spacing is >10x the median, the scan
                # started at a burst boundary — drop leading outliers.
                while valid and valid[0] > med * 10:
                    valid.pop(0)
            spacings = valid if valid else spacings
            etu = self._robust_min(spacings)
            # Sanity clamp: a real ISO 7816 etu is >= a few samples and below
            # ~100k samples even at extreme F/D.  Anything else is a glitch.
            if 4 <= etu <= 100000:
                self.bit_samples = etu
                self._etu_confirm_count = 0
                self._etu_fail_count = 0
        if self.bit_samples is None:
            self.bit_samples = self._compute_bit_samples()
            self._etu_confirm_count = 0
            self._etu_fail_count = 0
        # The live line is gated/stopped CLK; use the edge-list bit reader
        # (immune to the drift a fixed sample-skip cadence would suffer) for
        # every byte from here on.
        self._edge_read = True
        self.log("etu recovered (samples):", self.bit_samples)

    def _lock_etu_from_edges(self, min_spacings=6):
        '''Lock the ETU from the most recent DATA edge spacings.

        Used after the first few bytes of an ATR (which provide a clean,
        contiguous burst at the default ETU) to derive the actual bit period
        so the rest of the session is decoded at the correct speed.'''
        if len(self._edge_spacings) < min_spacings:
            return
        spacings = list(self._edge_spacings)
        etu = self._robust_min(spacings)
        if 4 <= etu <= 100000:
            self.bit_samples = etu
            self._etu_confirm_count = 3  # lock immediately
            self._etu_fail_count = 0
            self.log("ETU locked from ATR edges:", etu)

    def _confirm_etu(self, parity_ok):
        '''Validate ETU measurement after _measure_etu.  Call after each byte
        decode in _read_byte_edges.  After 3 successful decodes the
        measurement is locked.  If 2 consecutive parity errors occur before
        validation, the measurement is discarded and re-measured from the
        next burst.'''
        if self._etu_confirm_count >= 3:
            return
        if parity_ok:
            self._etu_confirm_count += 1
            if self._etu_confirm_count >= 3:
                self.log("ETU confirmed:", self.bit_samples)
        else:
            self._etu_fail_count += 1
            if self._etu_fail_count >= 2:
                self.log("ETU re-measure (bad initial measurement):",
                         self.bit_samples)
                self.bit_samples = None
                self._etu_confirm_count = 0
                self._etu_fail_count = 0

    def _robust_min(self, spacings):
        '''Smallest spacing that recurs (>=3x): the true etu.  Two
        consecutive differing bits produce a 1-etu gap, so a real bit period
        recurs often; a glitch is unique.  Falls back to the raw minimum.

        Spacings below MIN_ETU (12 samples at 16 MHz) are rejected as
        metastability glitches — they are too short for any valid ISO 7816
        bit period and would otherwise be picked as the "minimum recurring"
        spacing by the counter.'''
        MIN_ETU = 12
        from collections import Counter
        c = Counter(s for s in spacings if s >= MIN_ETU)
        for v in sorted(c):
            if c[v] >= 3:
                return v
        # Fallback: accept any spacing >= MIN_ETU, or raw min if nothing qualifies.
        valid = [s for s in spacings if s >= MIN_ETU]
        return min(valid) if valid else min(spacings)

    def _bits_at(self, e, edges, bs):
        '''Reconstruct the 10 bits (start + 8 data + parity) of the byte whose
        start-bit fall is at sample e, from the DATA edge list.  Returns None
        only if `e` is not a genuine start (no following edge).'''
        bits = []
        for k in range(10):
            m = e + round((k + 0.5) * bs)
            val = 1
            for (s, v) in edges:
                if s <= m:
                    val = v
                else:
                    break
            # Inverse convention (TS=0x3F): logic 1 = LOW, logic 0 = HIGH.
            if self._inverse_convention:
                val = 1 - val
            bits.append(val)
        return bits

    def _next_start_fall(self, edges, after):
        '''First FALL (1->0) strictly after sample `after` = next byte start.'''
        for (s, v) in edges:
            if s > after and v == 0:
                return s
        return None

    def _wait_clk_rising(self, n):
        '''Wait for n CLK rising edges.  Returns False on end-of-capture.

        CLK runs continuously for the whole of a character (Clock Stop only
        happens between characters), so within a byte it is safe to skip most
        of the way by samples and then land on the exact rising edge.  This
        keeps the edge-exactness of CLK-edge timing without paying one wait()
        per CLK cycle.  Lands within +/-1 CLK cycle of the target edge, which
        is far inside the stable region of a bit (a bit is held for the whole
        ETU).'''
        if n <= 0:
            return True
        if self._samples_per_clock and n > 2:
            # Skip (n - 2) cycles by samples, then take the last 2 edges
            # exactly.  Undershooting by a cycle is harmless (the bit is
            # stable for the full ETU), and the final two edge waits re-align
            # us to a genuine CLK edge.
            skip = int((n - 2) * self._samples_per_clock)
            if skip > 0:
                self.wait({'skip': skip})
            n = 2
        for _ in range(n):
            pins = self.wait({self.CLK_IDX: 'r'})
            if pins is None:
                self._eof = True
                return False
        return True

    def _read_byte_clk(self):
        '''Decode a single byte using CLK-edge counting for bit timing.

        Counts clock_skip CLK rising edges per ETU and samples DATA at the bit
        centers (1.5, 2.5, ..., 9.5 ETU from the start-bit fall).  Because the
        bit value is held stable for the whole ETU, sampling near the centre
        is exact for ANY byte -- including 0x00 / 0xff, which have too few DATA
        transitions for the edge-list reader to anchor reliably.

        Safe across Clock Stop Mode: CLK is never stopped mid-character, and
        it always resumes a few cycles before the next start bit (the guard
        time), so once wait_data_falling() has found a start bit, CLK is
        running for the whole frame.  clock_skip is protocol-defined (372 for
        the ATR, FI/DI after PPS), so no runtime ETU measurement is needed on
        the native path -- this is what makes decoding deterministic.'''
        if self._start_fall is None:
            self.wait_data_falling()
            if self._eof:
                return 0x00
        e0 = self._start_fall
        self._start_fall = None
        self.ss = e0
        bs = self.clock_skip
        self.bits = [0]  # start bit (always low)
        prev_edges = 0
        for i in range(9):
            # bit centres at (1.5 + i) ETU from the start fall
            total = int(round((1.5 + i) * bs))
            if not self._wait_clk_rising(total - prev_edges):
                # End of capture mid-byte: pad so the frame stays 10 bits.
                while len(self.bits) < 10:
                    self.bits.append(self.bits[-1] if self.bits else 1)
                break
            prev_edges = total
            pins = self.wait({'skip': 0})
            if pins is None:
                self._eof = True
                while len(self.bits) < 10:
                    self.bits.append(self.bits[-1] if self.bits else 1)
                break
            bit = pins[self.DATA_IDX]
            # Inverse convention (TS=0x3F): logic 1 = LOW, logic 0 = HIGH.
            if self._inverse_convention:
                bit = 1 - bit
            self.bits.append(bit)
        self.es = self.samplenum
        self.signal_quality(1 if (self.bits.count(1) % 2 != 0) else 0)
        parity_ok = (self.bits.count(1) % 2 == 0)
        if (self.bits.count(1) % 2 != 0):
            self.log(self.samplenum, "CHKSUM ERROR: ", 0, "bits: ", self.bits)
            self.put(self.ss, self.samplenum, self.out_ann,
                     [0, ["CHKSUM ERROR bits={bits}".format(bits=self.bits)]])
        if self.bit_samples is not None:
            self._confirm_etu(parity_ok)
        byte = self.get_bytes(self.bits[1:9])
        # Stuck-line watchdog (same as the other readers).
        if (sum(self.bits) == 0):
            self.zero_run += 1
            if (self.zero_run == 32):
                self.log("I/O line reads all-zero for", self.zero_run,
                         "frames - stuck low? check pogo contact")
                try:
                    self.put(self.ss, self.samplenum, self.out_ann,
                             [Ann.ANN_WARN, ["I/O stuck low?"]])
                except Exception:
                    pass
        else:
            self.zero_run = 0
        self.log(self.samplenum, self.bits[1:9], " : ", "0x{:02x}".format(byte))
        self.put(self.ss, self.samplenum, self.out_ann, [1, [hex(byte)]])
        return byte

    def _read_byte_edges(self, bs):
        '''Decode a single byte from the DATA line using edge-list
        reconstruction (robust to Clock Stop Mode / gated CLK, where fixed
        sample-skip timing drifts).  Returns the byte, having set self.ss/es
        and queued the next start-bit position in self._start_fall.

        Jumps straight to DATA edges around the current start fall (O(edges),
        not O(samples)), collects ~11 etu of edges (one byte plus the gap to
        the next start bit), reconstructs the 10 bits from their actual
        positions, and leaves self._start_fall at the next byte so subsequent
        reads stay re-anchored (no cross-byte drift).  A large turn-around
        idle (CLK stopped between command and response) simply leaves
        _start_fall unset here, and the next read re-hunts via
        wait_data_falling().'''
        # Safety: if we were called without a queued start bit, hunt for one.
        if self._start_fall is None:
            self.wait_data_falling()
            if self._eof:
                return 0x00
        e0 = self._start_fall
        self._start_fall = None
        self.ss = e0
        # Collect DATA edges for this byte + the inter-byte gap.
        edges = [(e0, 0)]
        limit = e0 + int(11 * bs)
        last_sn = e0
        while True:
            pins = self.wait({self.DATA_IDX: 'e'})
            if pins is None:
                break
            sn = self.samplenum
            if sn <= last_sn:
                break
            last_sn = sn
            edges.append((sn, pins[self.DATA_IDX]))
            if sn > limit:
                break
        bits = self._bits_at(e0, edges, bs)
        # Keep the spacings for ETU locking; the first few bytes of an ATR
        # provide the most reliable reference for the actual bit period.
        if len(edges) >= 2:
            for i in range(1, len(edges)):
                self._edge_spacings.append(edges[i][0] - edges[i - 1][0])
        if bits is None:
            self.bits = []
            byte = 0
        else:
            self.bits = bits
            byte = self.get_bytes(bits[1:9])
            nxt = self._next_start_fall(edges, e0 + int(10 * bs))
            if nxt is not None:
                self._start_fall = nxt
        self.es = self.samplenum
        self.signal_quality(1 if (self.bits.count(1) % 2 != 0) else 0)
        parity_ok = (self.bits.count(1) % 2 == 0)
        if (self.bits.count(1) % 2 != 0):
            self.log(self.samplenum, "CHKSUM ERROR: ", 0, "bits: ", self.bits)
            self.put(self.ss, self.samplenum, self.out_ann,
                     [0, ["CHKSUM ERROR bits={bits}".format(bits=self.bits)]])
        if self.bit_samples is not None:
            self._confirm_etu(parity_ok)
        if (sum(self.bits) == 0):
            self.zero_run += 1
            if (self.zero_run == 32):
                self.log("I/O line reads all-zero for", self.zero_run,
                         "frames - stuck low? check pogo contact")
                try:
                    self.put(self.ss, self.samplenum, self.out_ann,
                             [Ann.ANN_WARN, ["I/O stuck low?"]])
                except Exception:
                    pass
        else:
            self.zero_run = 0
        self.log(self.samplenum, self.bits[1:9], " : ", "0x{:02x}".format(byte))
        self.put(self.ss, self.samplenum, self.out_ann, [1, [hex(byte)]])
        return byte

    def wait_data_falling(self):
        '''Wait for the I/O start-bit falling edge, servicing optional
        RST/VCC line events while hunting.

        The bit period is measured directly from the DATA line in SAMPLES
        (not by counting CLK edges), so a frozen CLK during Clock Stop Mode
        cannot desync the decoder.  A start bit is accepted only after DATA
        has been HIGH for >= 1.5 bit periods (inter-character guard, rejects
        intra-byte edges / idle glitches).'''
        min_high = 4
        if self.bit_samples:
            if self._edge_read:
                # DATA must be HIGH (idle) for at least half an etu before a
                # fall is accepted as a start bit.  This rejects intra-byte
                # glitch falls yet still accepts the legitimate inter-byte gap
                # (the ~1-etu stop bit), which a 1.5-etu guard would wrongly
                # reject on fast ETUs (e.g. a phone SIM at ~53 samples/etu),
                # causing bytes to be skipped / 0x00 inserted.
                min_high = max(int(0.5 * self.bit_samples), 4)
            else:
                min_high = max(int(1.5 * self.bit_samples), 4)
        while True:
            # Wait for DATA idle, servicing RST/VCC.
            # In direct convention: idle = HIGH, start bit = falling edge (HIGH→LOW).
            # In inverse convention: idle = LOW, start bit = rising edge (LOW→HIGH).
            if self._inverse_convention:
                idle_cond = {self.DATA_IDX: 'l'}  # Wait for LOW (idle in inverse)
                start_edge = 'r'  # Rising edge = start bit in inverse
            else:
                idle_cond = {self.DATA_IDX: 'h'}  # Wait for HIGH (idle in direct)
                start_edge = 'f'  # Falling edge = start bit in direct
            cond = [idle_cond]
            if (self.track_rst):
                cond.append({self.RST_IDX: 'e'})
            if (self.track_vcc):
                cond.append({self.VCC_IDX: 'e'})
            while True:
                pins = self.wait(cond)
                if self._stall_check(pins):
                    self._eof = True
                    return
                if (self.line_events(pins)):
                    continue
                break
            hi_start = self.samplenum
            # Wait for the start-bit edge; re-anchor the high-start across
            # any line events so the measured guard stays accurate.
            cond2 = [{self.DATA_IDX: start_edge}]
            if (self.track_rst):
                cond2.append({self.RST_IDX: 'e'})
            if (self.track_vcc):
                cond2.append({self.VCC_IDX: 'e'})
            while True:
                pins = self.wait(cond2)
                if self._stall_check(pins):
                    self._eof = True
                    return
                if (self.line_events(pins)):
                    hi_start = self.samplenum
                    continue
                break
            if (self.samplenum - hi_start) < min_high:
                continue
            self._start_fall = self.samplenum
            return

    def _stall_check(self, pins):
        '''Detect end-of-capture: libsigrokdecode stops advancing the sample
        counter once the feed is exhausted, so a wait that returns the same
        sample number repeatedly means there is no more data.'''
        if pins is None:
            return True
        if self._prev_wait_sn is not None and self.samplenum == self._prev_wait_sn:
            self._stall += 1
        else:
            self._stall = 0
        self._prev_wait_sn = self.samplenum
        return self._stall > 4

    def read_byte(self):
        if self._replay:
            return self._replay.popleft()
        if (self.peeked_byte != None):
            byte = self.peeked_byte
            self.peeked_byte = None
            self.peeked_samplenum = -1
            return byte;
        # In edge-read (mid-session, gated-CLK) mode the next start bit is
        # already queued by _read_byte_edges, so re-hunting would wrongly
        # reject the short inter-byte gap.  Otherwise re-hunt normally.
        if not (self._edge_read and self._start_fall is not None):
            self.wait_data_falling()
        return self.read_byte_no_wait()

    def peek_byte(self):
        if self._replay:
            return self._replay[0]
        if (self.peeked_byte != None):
            return self.peeked_byte
        if not (self._edge_read and self._start_fall is not None):
            self.wait_data_falling()
        self.peeked_samplenum = self._start_fall
        self.peeked_byte = self.read_byte_no_wait()
        return self.peeked_byte

    def read_byte_no_wait(self):
        self.bits = []
        if (self.sample_as_clock):
            # Experimental mode: DATA doubles as the clock.  Keep the
            # original sample-as-clock reader (bits sampled on the DATA
            # edge, with no separate timing measurement).
            self.ss = self.samplenum
            self.clock_skip = 0
            pins = self.wait({1: 'r'})
            self.clock_skip = self.samplenum - self.ss + 2
            self.detected_clock_skip = self.clock_skip
            self.wait({'skip': int(self.clock_skip / 3)})
            self.bits.append(0)
            for x in range(9):
                pins = self.wait({'skip': 0})
                bit = pins[1]
                # Inverse convention (TS=0x3F): logic 1 = LOW, logic 0 = HIGH.
                if self._inverse_convention:
                    bit = 1 - bit
                self.bits.append(bit)
                self.wait({'skip': self.clock_skip - 4})
            self.es = self.samplenum
            self.signal_quality(1 if (self.bits.count(1) % 2 != 0) else 0)
            if (self.bits.count(1) % 2 != 0):
                self.log(self.samplenum, "CHKSUM ERROR: ", pins[1], "bits: ", self.bits)
                self.put(self.ss, self.samplenum, self.out_ann, [0, ["CHKSUM ERROR bits={bits}".format(bits=self.bits)]])
            byte = self.get_bytes(self.bits[1:9])
            if (sum(self.bits) == 0):
                self.zero_run += 1
                if (self.zero_run == 32):
                    self.log("I/O line reads all-zero for", self.zero_run,
                             "frames - stuck low? check pogo contact")
                    try:
                        self.put(self.ss, self.samplenum, self.out_ann,
                                 [Ann.ANN_WARN, ["I/O stuck low?"]])
                    except Exception:
                        pass
            else:
                self.zero_run = 0
            self.log(self.samplenum, self.bits[1:9], " : ", "0x{:02x}".format(byte))
            self.put(self.ss, self.samplenum, self.out_ann, [1, [hex(byte)]])
            return byte
        # Normal path.  Two bit readers are available:
        #  - CLK-synchronous (_read_byte_clk): exact CLK-edge timing, used in
        #    native mode where a real CLK channel is present.  Handles 0x00 /
        #    0xff perfectly and is deterministic.
        #  - Edge-list (_read_byte_edges): DATA-edge reconstruction, used for
        #    the non-native clock modes (sample_as_clock / detect) and as a
        #    fallback when clock_skip has not been established yet.
        #  Callers (read_byte / peek_byte / read_first_byte) ensure
        #  _start_fall is set before calling here.
        if self._use_clk_sync():
            return self._read_byte_clk()
        return self._read_byte_edges(self.bit_samples or self._compute_bit_samples())

    def _use_clk_sync(self):
        '''True when the CLK-synchronous reader should be used.

        Only in native clock mode (a real CLK channel) AND only when
        clock_skip is known to be correct (_clock_skip_confident).  In
        sample_as_clock / detect modes there is no usable CLK signal, and on
        a mid-session capture clock_skip is unknown until recovered -- in
        both cases the edge-list DATA reader (driven by bit_samples) is the
        safe fallback.'''
        return (not (self.sample_as_clock or self.detect_clock)
                and self._clock_skip_confident)


    def resync_idle(self):
        '''Re-align framing after a desync: wait for DATA to go to idle level
        so the next peek lands on a genuine start bit of a fresh exchange
        instead of a mid-burst byte.  Gating-immune: we poll DATA in
        samples (which advance even when CLK is frozen), and bound the hunt
        by a sample budget so a pathologically-busy (or stuck) line never
        stalls the decoder.'''
        bs = self.bit_samples or self._compute_bit_samples()
        budget = int(IDLE_RESYNC_ETU * bs) * 8
        step = max(int(bs), 1)
        loops = budget // step + 16
        # In direct convention: idle = HIGH (mark).
        # In inverse convention: idle = LOW (mark is inverted).
        idle_level = 0 if self._inverse_convention else 1
        for _ in range(loops):
            pins = self.wait({'skip': 0})
            if pins[self.DATA_IDX] == idle_level:
                return
        # Could not find an idle gap -- resume normal decode anyway.

    def handle_atr(self, pins):
        
        atr_start = self.samplenum;

        self.log("START ATR:", self.samplenum);
        self.state = 'ATR'
        
        tA = []
        tB = []
        tC = []
        tD = []
        historicalBytes = []
        self.ATR = []
        # Clear any stale edge spacings; the first few ATR bytes give us the
        # most reliable ETU reference for the whole session.
        self._edge_spacings.clear()
        # Try to lock the ETU from the actual CLK frequency before reading the
        # first ATR byte.  This removes the hard-coded clock_skip*3 estimate.
        # For ATR-included captures, save/restore samplenum so _measure_clock_period
        # doesn't consume the initial DATA HIGH period that wait_data_falling needs.
        if self._samples_per_clock is None:
            saved_sn = self.samplenum
            self._measure_clock_period()
            if self.starts_with_atr:
                self.samplenum = saved_sn
        # Ensure the sample-domain ETU is available for framing
        # (wait_data_falling / resync_idle) even though the CLK-sync reader
        # itself only needs clock_skip.
        if self.bit_samples is None:
            self.bit_samples = self._compute_bit_samples()

        if (self.peeked_byte != None):
            atr_start = self.peeked_samplenum
            byte = self.read_byte()
        else:
            byte = self.read_first_byte()
            atr_start = self.ss
        # TS must be 0x3B (direct) or 0x3F (inverse) per TS 102 221 §5.2.2.
        # Pre-activation traffic (reader card-detect polling, a stray PPS
        # `ff 10 95 7a`, power-up noise) can appear on DATA before RST even
        # deasserts.  Resync past those instead of mis-parsing them as the
        # ATR and permanently desyncing the session.
        ts_attempts = 0
        while (byte not in (0x3b, 0x3f) and ts_attempts < 64):
            # Command-detect: a plausible CLA immediately followed by a
            # plausible INS is the start of a command, not an ATR.  Hand the
            # header back to the DATA state for normal T=0 framing instead of
            # silently skipping it as an "invalid TS" byte (this is how a
            # SELECT was being lost while the decoder hunted for an ATR that
            # was not coming).  The full 5-byte header is still validated in
            # the DATA state; ambiguous frames are emitted flagged, not dropped.
            #
            # CLA=0x00 is excluded: it's technically valid for interindustry
            # commands, but during ATR hunt it's overwhelmingly noise (the
            # real SELECT that was lost used CLA=0x00 and appeared *after* the
            # ATR, not during the hunt).  Including it causes false positives
            # on noise like the 0x00 0x1E seen in the live test.
            if plausible_cla(byte) and byte != 0x00:
                nxt = self.peek_byte()
                if plausible_ins(nxt):
                    self._replay.appendleft(byte)
                    self.hasT0 = True
                    self.hasT1 = False
                    self.state = 'DATA'
                    self.log("Command header 0x{cla:02x} 0x{ins:02x} during ATR hunt; decoding as command".format(cla=byte, ins=nxt))
                    return
            self.log("Invalid TS byte 0x{byte:02x} (pre-activation?), resyncing".format(byte=byte))
            self.put(atr_start, self.samplenum, self.out_ann,
                     [Ann.ANN_WARN, ["Invalid TS byte 0x{byte:02x} - skipped".format(byte=byte)]])
            byte = self.read_byte()
            atr_start = self.ss
            ts_attempts += 1
        if (byte not in (0x3b, 0x3f)):
            self._atr_hunt_count += 1
            # No valid ATR found this round -- go back to hunting for the
            # next falling edge.  Never fabricate a synthetic ATR: a stray
            # 0x3B/0x3F byte inside command traffic (e.g. the FID '3F00' of a
            # SELECT) would otherwise be mis-committed as a fake 2-byte ATR
            # and destroy the surrounding command.  The hunt is bounded by
            # _atr_hunt_count only to avoid logging forever on a dead line.
            if (self._atr_hunt_count < 8):
                self.log("No valid TS byte, back to FIND START (hunt {count})".format(count=self._atr_hunt_count))
                self.state = 'FIND START'
                return
            if byte == 0xFF:
                self.log("line appears idle (all 0xFF), resetting ATR hunt")
                self._atr_hunt_count = 0
                self.state = 'FIND START'
                return
            # Give up hunting for an ATR here without emitting anything;
            # resume T=0 framing from the next byte instead of inventing one.
            self.log("No valid ATR after {count} hunts; resuming DATA without synthetic ATR".format(count=self._atr_hunt_count))
            self.hasT0 = True
            self.hasT1 = False
            self.state = 'DATA'
            self._resync = True
            if (self.options['protocol'] == "T=0"):
                self.hasT0 = True
                self.hasT1 = False
            elif (self.options['protocol'] == "T=1"):
                self.hasT0 = False
                self.hasT1 = True
            return
        else:
            self._atr_hunt_count = 0
        self.ATR.append(byte)
        # TS=0x3F means inverse convention: logic 1 = LOW, logic 0 = HIGH.
        # All subsequent byte reads must invert bits.
        self._inverse_convention = (byte == 0x3f)
        self.log("TS=0x{ts:02x} ({conv} convention)".format(
            ts=byte, conv="inverse" if self._inverse_convention else "direct"))

        t0 = self.read_byte()
        self.ATR.append(t0)
        # Lock ETU from the first two ATR bytes (TS + T0).  The ATR is sent
        # at the default ETU, so its edge spacings are the authoritative
        # timing reference for the rest of the session (until PPS changes it).
        # Temporarily disabled: measurement is unstable on some captures.
        # if self.bit_samples is None:
        #     self._lock_etu_from_edges(min_spacings=6)

        firstT0 = t0

        self.hasT0 = False
        self.hasT1 = False
        self.hasT15 = False
        while (firstT0 & 0b11110000):
            # Defense-in-depth: a valid ISO 7816 ATR is at most 33 bytes.
            # If the parse runs past that (e.g. a noise byte slipped in as
            # TS and the TD chain never terminates), abandon the parse and
            # hunt again rather than commit a giant bogus ATR.
            if (len(self.ATR) > 33):
                self.log("ATR exceeds 33 bytes (noise-induced?), abandoning parse")
                self._atr_hunt_count += 1
                self.state = 'FIND START'
                return
            if (firstT0 & 0b00010000):
                byte = self.read_byte()
                tA.append(byte)
                self.ATR.append(byte)
            if (firstT0 & 0b00100000):
                byte = self.read_byte()
                tB.append(byte)
                self.ATR.append(byte)
            if (firstT0 & 0b01000000):
                byte = self.read_byte()
                tC.append(byte)
                self.ATR.append(byte)
            if (firstT0 & 0b10000000):
                byte = self.read_byte()
                if ((byte & 0x0F) == 0):
                    self.hasT0 = True
                elif ((byte & 0x0F) == 1):
                    self.hasT1 = True
                elif ((byte & 0x0F) == 15):
                    self.hasT15 = True
                else:
                    self.log("Invalid Protocol in ATR: ", "T=",(byte & 0x0F))    
                    self.put(atr_start, self.samplenum, self.out_ann, [0, ["Invalid Protocol in ATR T={protocol}".format(protocol=(byte & 0x0F))]])
                tD.append(byte)
                self.ATR.append(byte)
                firstT0 = byte
                self.log("TD("+str(len(tD))+"): ", hex(firstT0), "T=",(byte & 0x0F))
            else:
                firstT0 = 0;

        for _ in range(0, t0 & 0x0F):
            byte = self.read_byte()
            self.ATR.append(byte)
        
        if (self.hasT1 == False and self.hasT0 == False):
            self.hasT0 = True

        if (self.hasT1 == True or self.hasT15):
            byte = self.read_byte()
            self.ATR.append(byte)
            xor = 0
            for i in range(1, len(self.ATR)): xor = xor ^ self.ATR[i]
            if (xor != 0):
                self.put(atr_start, self.samplenum, self.out_ann, [0, ["Invalid TCK in ATR, got={tck:02x} expected={xor:02x}".format(tck=byte,xor=xor)]])
                self.log("Invalid TCK in ATR", hex(byte), hex(xor))    

        self.put(atr_start, self.samplenum, self.out_ann, [2, ["ATR", "ATR={atr}".format(atr=codecs.encode(bytes(self.ATR), 'hex'))]])
        self.put(atr_start, self.samplenum, self.out_python, [0, self.ATR])
        self.emit_packet(GSMTAP_SIM_ATR, bytes(self.ATR), atr_start, self.samplenum)

        self.log("ENDATR", codecs.encode(bytes(self.ATR), 'hex'))
        self._atr_parsed = True
        # A real ATR was parsed at the default rate, so clock_skip=372 is now
        # confirmed correct -- the CLK-sync reader is trusted from here on.
        self._clock_skip_confident = True
        # The ATR is always sent at the default rate (372 CLK/bit).
        # _measure_etu() may have inflated clock_skip via inter-byte gap
        # averaging; reset to 372 so PPS (also at the default rate) is
        # read at the correct bit boundary.
        self.clock_skip = 372
        # Also lock bit_samples so the mid-session re-measure (line 1633)
        # does not re-run and overwrite clock_skip=372 with a wrong value
        # derived from pre-ATR edge spacings.  _confirm_etu() may have
        # cleared bit_samples during ATR hunt (parity failures on noise),
        # which would trigger _measure_etu() on the next decode_step.
        self.bit_samples = self.clock_skip * (self._samples_per_clock or 3)
        # Lock the ETU so _confirm_etu() cannot clear bit_samples after
        # parity failures on post-ATR noise bytes.  Without this, two
        # consecutive parity errors would trigger an ETU re-measure that
        # overwrites clock_skip=372 with a wrong value from pre-ATR data.
        self._etu_confirm_count = 3
        self._etu_fail_count = 0
        self.state = 'DATA'
        self._resync = True  # Wait for inter-frame idle gap before reading commands
        # PPS may be attempted once after this ATR.
        self._pps_attempted = False

        if (self.options['protocol'] == "T=0"):
            self.hasT0 = True
            self.hasT1 = False
        elif (self.options['protocol'] == "T=1"):
            self.hasT0 = False
            self.hasT1 = True

    def t1_parse_block(self, es):
        packet = []
        lrc = 0;
        nad = self.read_byte()
        lrc = lrc ^ nad
        self.put(es, self.samplenum, self.out_ann, [1, "NAD:" + hex(nad)])
        sad = nad & 0x70
        dad = nad & 0x07
        self.log("T=1 NAD=", hex(nad), "SAD=", hex(sad), "DAD=", hex(dad))
        
        pcb = self.read_byte()
        lrc = lrc ^ pcb
        
        isSBlock = False
        isRBlock = False
        isIBlock = False
        if (pcb & 0b11000000 == 0b11000000):
            # S-Block
            isSBlock = True
            self.put(es, self.samplenum, self.out_ann, [3, "PCB S " + hex(pcb)])
            self.log("PCB S-Block", hex(pcb & 0b00111111))
        elif (pcb & 0b10000000 == 0b10000000):
            # R-Block
            isRBlock = True
            self.put(es, self.samplenum, self.out_ann, [3, "PCB R " + hex(pcb)])
            self.log("PCB R-Block", hex(pcb & 0b00111111))
        else:
            # I-Block
            isIBlock = True
            self.put(es, self.samplenum, self.out_ann, [3, "PCB I " + hex(pcb)])
            self.log("PCB I-Block", hex(pcb))

        bLen = self.read_byte()
        lrc = lrc ^ bLen
        if (bLen > 0):
            for _ in range(bLen): 
                byte = self.read_byte()
                lrc = lrc ^ byte
                if (isIBlock): packet.append(byte)
        
        # CRC to implement
        bLrc =  self.read_byte()
        lrc = lrc ^ bLrc

        if (lrc != 0):
            self.put(es, self.samplenum, self.out_ann, [0, ["Invalid checksum on T=1 block, , got={got:02x} expected={expected:02x}".format(got=lrc,expected=bLrc)]])
            self.log("Invalid checksum on T=1 block", hex(lrc), hex(bLrc))

        self.log("block_content", codecs.encode(bytes(packet), 'hex'))

        if (isIBlock):
            self.put(es, self.samplenum, self.out_ann, [6, ["I-Block", "I-Block len={len} isMultiBlock={multi}".format(len=bLen,multi=(pcb & 0b00100000 > 0))]])
        if (isRBlock):
            self.put(es, self.samplenum, self.out_ann, [7, ["R-Block", "R-Block flag={flag:02x}".format(flag=pcb & 0b00111111)]])
        if (isSBlock):
            self.put(es, self.samplenum, self.out_ann, [8, ["S-Block", "S-Block flag={flag:02x}".format(flag=pcb & 0b00111111)]])

        if (isIBlock and pcb & 0b00100000): # m-flag
            self.log("T=1 Multiblock flag", hex(pcb))
            for _ in range(32):  # bounded: garbage must not loop forever
                isIBlock2,packet2 = self.t1_parse_block(self.samplenum)
                if (isIBlock2):
                    packet = packet + packet2
                    break
        

        return isIBlock,packet;
    
    def handle_pps(self):
        # Mark PPS attempted so idle 0xFF bytes after a failed/no-PPS
        # scenario do not loop back into PPS detection indefinitely.
        self._pps_attempted = True
        lrc = 0
        ss = self.peeked_samplenum
        pps = self.read_byte()
        pps_req = [pps]
        pps0 = self.read_byte()
        pps_req.append(pps0)
        # An idle I/O line idles HIGH (repeated 0xFF).  A genuine PPS0 always
        # has its reserved bits clear (bit7 and bits 0..3 == 0), so the value
        # is one of 0x00/0x10/0x20/.../0x70.  0xFF (or any byte with bit7 or
        # low nibble set) is not a PPS0 -- it is idle noise.  Without this
        # guard an idle line is mis-read as an endless stream of "PPS accepted"
        # and real APDUs are never reached.
        if (pps0 & 0x8F) != 0:
            self.log("0xFF followed by 0x%02x is not a valid PPS0 - idle line, skipping" % pps0)
            self._resync = True
            return
        pps1 = 0; pps2 = 0; pps3 = 0
        if (pps0 & 0b00010000):
            pps1 = self.read_byte()
            pps_req.append(pps1)
            lrc = lrc ^ pps1
        if (pps0 & 0b00100000):
            pps2 = self.read_byte()
            pps_req.append(pps2)
            lrc = lrc ^ pps2
        if (pps0 & 0b01000000):
            pps3 = self.read_byte()
            pps_req.append(pps3)
            lrc = lrc ^ pps3
        pck = self.read_byte()
        pps_req.append(pck)
        lrc = lrc ^ pps ^ pps0 ^ pck
        if (lrc != 0):
            self.put(ss, self.samplenum, self.out_ann, [0, ["INVALID Checksum on PPS Request, got={got:02x} expected={expected:02x}".format(got=pck,expected=(lrc ^ pps ^ pps0))]])
            self.log("INVALID Checksum on PPS Request", hex(lrc))
        
        r_lrc = 0
        r_pps = self.read_byte()
        pps_rsp = [r_pps]
        r_pps1 = 0; r_pps2 = 0; r_pps3 = 0
        if (r_pps != 0xFF):
            self.put(ss, self.samplenum, self.out_ann, [0, ["PPS Request not confirmed"]])
            self.log("PPS Request not confirmed", r_pps)
        r_pps0 = self.read_byte()
        pps_rsp.append(r_pps0)
        if (r_pps0 & 0b00010000):
            r_pps1 = self.read_byte()
            pps_rsp.append(r_pps1)
            r_lrc = r_lrc ^ r_pps1
        if (r_pps0 & 0b00100000):
            r_pps2 = self.read_byte()
            pps_rsp.append(r_pps2)
            r_lrc = r_lrc ^ r_pps2
        if (r_pps0 & 0b01000000):
            r_pps3 = self.read_byte()
            pps_rsp.append(r_pps3)
            r_lrc = r_lrc ^ r_pps3
        r_pck = self.read_byte()
        pps_rsp.append(r_pck)
        r_lrc = r_lrc ^ r_pps ^ r_pps0 ^ r_pck
        if (r_lrc != 0):
            self.put(ss, self.samplenum, self.out_ann, [0, ["INVALID Checksum on PPS Response, got={got:02x} expected={expected:02x}".format(got=r_pck,expected=(r_lrc ^ r_pps ^ r_pps0))]])
            self.log("INVALID Checksum on PPS Response", hex(r_lrc))
        
        if (pps0 == r_pps0 and pps1 == r_pps1 and pps2 == r_pps2 and pps3 == r_pps3):
            if (self.detect_clock or self.sample_as_clock):
                # .get() with spec defaults: unknown FI/DI codes from a
                # corrupted PPS1 must not raise KeyError or divide by zero.
                tmp_fi = self.clock_rate.get(int(pps1 >> 4), 372)
                tmp_di = self.baud_rate.get(int(pps1 & 0x0F), 1)
                if tmp_di == 0:
                    self.log("Corrupted PPS: DI=0 (invalid)")
                    return
                tmp_clock_skip = int(tmp_fi / tmp_di)                
                self.log("Received PPS change: FI", tmp_fi, "DI", tmp_di, "clock_skip", tmp_clock_skip)
                self.clock_skip = int(tmp_clock_skip * self.detected_clock_skip / 372)
                self.fi = tmp_fi
                self.di = tmp_di
                self.log("PPS Success new settings (calculated): FI", self.fi, "DI", self.di, "clock_skip", self.clock_skip)
            else:
                # Native CLK mode: clock_skip counts real CLK edges per
                # data bit.  After an ACCEPTED PPS both sides switch the
                # UART to F/D cycles per bit (e.g. 512/16 = 32 edges),
                # so the decoder must follow the switch.  Live capture
                # proof: ATR+PPS decode cleanly at 372, everything after
                # aliases into garbage if clock_skip stays at 372.
                self.fi = self.clock_rate.get(int(pps1 >> 4), 372)
                self.di = self.baud_rate.get(int(pps1 & 0x0F), 1)
                self.clock_skip = max(int(self.fi // self.di), 1)
                self.log("PPS accepted: FI", self.fi, "DI", self.di, "clock_skip", self.clock_skip)
            # PPS changed the bit rate.  How we follow it depends on the reader:
            #
            #  - Native CLK-sync reader (_use_clk_sync): clock_skip is the ONLY
            #    timing input -- the CLK period is unchanged by PPS, so the new
            #    ETU is exactly clock_skip * samples_per_clock.  No DATA
            #    re-measurement is needed (and none should happen: consuming a
            #    burst here would silently drop the first post-PPS command).
            #    Just refresh bit_samples for wait_data_falling / edge fallback.
            #
            #  - Edge-list reader (non-native modes): there is no usable CLK
            #    reference, so re-measure the ETU from the live DATA line on
            #    the next decode cycle; that burst is emitted flagged, not
            #    silently consumed.
            # PPS changed the bit rate.  How we follow it depends on the mode:
            #
            #  - Native CLK mode (real CLK channel): after an ACCEPTED PPS the
            #    card and terminal switch to FI/DI CLK cycles per bit, and the
            #    CLK period itself is unchanged.  So clock_skip = FI/DI is
            #    exact -- no DATA re-measurement is needed (and none should
            #    happen: consuming a burst here would silently drop the first
            #    post-PPS command).  Just refresh bit_samples for
            #    wait_data_falling / the edge-list fallback.
            #
            #  - sample_as_clock / detect modes: there is no usable CLK
            #    reference, so re-measure the ETU from the live DATA line on
            #    the next decode cycle; that burst is emitted flagged, not
            #    silently consumed.
            if not (self.sample_as_clock or self.detect_clock):
                self.bit_samples = self._compute_bit_samples()
                self._pps_speed_changed = False
                # Re-hunt for the next start bit after the PPS response.
                self._start_fall = None
            else:
                self._pps_speed_changed = True
                self.bit_samples = None
                self._start_fall = None
            # clock_skip now reflects the negotiated FI/DI, so it is known to
            # be correct regardless of which reader is active.
            self._clock_skip_confident = True
        else:
            self.log("INVALID PPS. Request & Response not matching.", hex(r_lrc))       
            self.put(ss, self.samplenum, self.out_ann, [0, ["INVALID PPS. Request & Response not matching"]])
        self.put(ss, self.samplenum, self.out_ann, [3, ["PPS", "PPS DI={di} FI={fi} clock_skip={clock_skip}".format(di=self.di,fi=self.fi,clock_skip=self.clock_skip)]])
        self.emit_packet(GSMTAP_SIM_PPS, bytes(pps_req + pps_rsp), ss, self.samplenum)


    def decode_step(self):
        '''Run one state-machine step. Returns False when decoding ends.'''
        # End-of-capture detection: libsigrokdecode stops advancing the sample
        # counter once the feed is exhausted, so a stuck sample number means
        # we have consumed everything (and any pending wait is non-blocking).
        if self.samplenum == self._last_sn or self._eof:
            return False
        self._last_sn = self.samplenum
        # State machine.
        if self.state == 'FIND START':
            # Find the first frame (sample-based, gating-immune) and hand it
            # to the ATR hunter.  RST/VCC edges are still serviced inside
            # wait_data_falling via track_rst/track_vcc.
            while True:
                byte = self.read_first_byte()
                self.peeked_byte = byte
                self.peeked_samplenum = self.ss
                self.handle_atr(self.wait({'skip': 0}))
                break
        elif self.state == 'DATA':
            packet = [];

            # Mid-session capture with an explicit protocol: there is no ATR to
            # derive the bit period from, so recover it once from the live line
            # and then fall through to the normal T=0/T=1 framing state machine
            # below, which reassembles each full command+response exchange into
            # a single GSMTAP APDU.  (Emitting each idle-split burst verbatim
            # produced fragments, because the card stops CLK during the
            # turn-around and every exchange is split across idle gaps.)
            #
            # Also re-measure after an accepted PPS changes the bit rate:
            # the old ETU no longer applies and the new one must be measured
            # from the live DATA line.
            if self.bit_samples is None and (self.starts_with_atr is False or self._pps_speed_changed):
                self._pps_speed_changed = False
                # For the CLK-sync reader we also need clock_skip, which is
                # unknown on a mid-session capture.  Measure the CLK period
                # (samples per CLK cycle) and the ETU (samples per bit), then
                # derive clock_skip = ETU / CLK-period so the CLK-sync reader
                # runs at the true rate.  If the CLK period cannot be measured
                # (fully gated CLK), clock_skip stays unconfident and the
                # edge-list reader (bit_samples-driven) is used instead.
                if self._samples_per_clock is None:
                    self._measure_clock_period()
                self._measure_etu()
                if self._eof:
                    return False
                self._derive_clock_skip_from_etu()
                return True
                # ETU now known: run the standard framing below.

            # After a desync, re-align on an inter-frame idle gap so the
            # next exchange is read from a real command boundary.
            if (self._resync):
                self._resync = False
                self.resync_idle()

            # Opportunistic RST/VCC level check at packet boundary.
            # Note: edges occurring entirely inside a packet transfer
            # are only detected here as a net level change.
            if (self.track_rst or self.track_vcc):
                self.line_events(self.wait({'skip': 0}))

            if not self.hasT0 and not self.hasT1:
                bs = self.bit_samples or self._compute_bit_samples()
                self.wait({'skip': int(bs)})
                return True

            firstByte = self.peek_byte();
            if (firstByte == 0xFF): # PPS Request
                # Only one PPS attempt is made after an ATR/warm reset.
                # Idle 0xFF bytes after a failed/no-PPS scenario would
                # otherwise trigger PPS detection in an infinite loop.
                if not self._pps_attempted:
                    self.handle_pps();
                else:
                    # Idle 0xFF noise after the PPS window has closed.
                    # Consume it and re-sync on the next real start bit.
                    self.read_byte()
                    self._resync = True
                return True
            elif (firstByte == 0x3b) and not self._atr_parsed: # Probably ATR (only if no ATR yet)
                self.handle_atr(self.wait({'skip': 0}))
                return True
            elif bin(firstByte).count('1') >= 6:
                # Idle-line noise: byte has 6+ bits set (all-1s with
                # 0-2 bit errors).  Re-sync instead of mis-parsing as
                # a T=0 header (which would pack idle noise into
                # garbage APDUs).
                self.peeked_byte = None  # consume the peeked byte
                self._resync = True
                return True
            elif not plausible_cla(firstByte):
                # Non-standard CLA: byte is not a recognized ISO 7816
                # class.  Likely mis-framed data — attempt to resync.
                self.peeked_byte = None  # consume the peeked byte
                self.log("Suspicious CLA 0x{:02x}, attempting resync".format(firstByte))
                self.put(self.peeked_samplenum, self.peeked_samplenum,
                         self.out_ann, [Ann.ANN_WARN,
                                        ["Suspicious CLA 0x{:02x}".format(firstByte)]])
                self._resync = True
                return True
            elif firstByte == 0x00 and self.zero_run >= 32:
                # Stuck-low noise: I/O held low for many consecutive frames.
                # Don't start a T=0 frame with leading zeros.
                self.peeked_byte = None
                self._resync = True
                return True

            es = self.peeked_samplenum;
            if (self.hasT0):
                # Idle-line check before reading the command header.
                # DATA idles HIGH in direct convention (0xFF) or LOW in
                # inverse convention (0x00).  If the first byte is idle,
                # the card is not transmitting — skip it and let the RST
                # handler re-arm ATR hunt.
                idle_byte = 0xFF if not self._inverse_convention else 0x00
                first = self.peek_byte()
                if first == idle_byte:
                    self.peeked_byte = None
                    self._resync = True
                    return True
                bClass = self.read_byte()
                bIns = self.read_byte()
                p1 = self.read_byte()
                p2 = self.read_byte()
                p3 = self.read_byte()
                packet.extend((bClass, bIns, p1, p2, p3))
                # All-zero header is never a valid T=0 command.
                if all(b == 0 for b in packet[:5]):
                    self.put(es, self.samplenum, self.out_ann,
                             [Ann.ANN_WARN,
                              ["all-zero T=0 header (stuck low?)"]])
                    self._resync = True
                    return True
                # T=0 header validation per ISO 7816-4 §12.1.1.
                # Rejects noise headers that slip past the CLA filter.
                #  - INS=0x00 is reserved/invalid.
                #  - MSB nibble 0x6/0x9 conflicts with status words.
                #  - LSB must be 0 (all standard interindustry commands).
                if (bIns == 0x00
                        or (bIns & 0xF0) == 0x60
                        or (bIns & 0xF0) == 0x90
                        or (bIns & 0x01) != 0):
                    self._resync = True
                    return True
                # T=0 procedure-byte transport (ISO 7816-3 §10.3.3/10.3.4).
                # Reassemble the exchange to ISO 7816-4 form (C-APDU = header
                # + command data, R-APDU = response data + SW1 SW2) into one
                # event.  Procedure bytes (ACK == INS, NULL 0x60, 9E/9F) are
                # framing and omitted.
                got_sw = False
                if self._edge_read:
                    # Mid-session (gated-CLK) path.
                    #
                    # T=0 case 3/4 commands carry Lc (= P3) command-data bytes
                    # on the wire IMMEDIATELY after the 5-byte header, BEFORE
                    # the card's first procedure byte.  The original loop (which
                    # treats the first post-header byte as a procedure byte)
                    # therefore mis-frames them.  We distinguish the cases by
                    # the card's first procedure byte:
                    #   * ACK (== INS or ~INS) right after the header  -> case 2/4, the
                    #     terminal sent no command data and the card is
                    #     acknowledging; read P3 response bytes (+SW), or, for
                    #     Le == 0 (GET RESPONSE), read until the SW.
                    #   * any other byte                        -> case 3/4, it
                    #     is terminal command data; read P3 command-data bytes,
                    #     then the card's procedure byte (ACK/SW/9x).
                    pb0 = self.read_byte()
                    # Skip NULL (0x60) procedure bytes: the card may send
                    # NULLs while processing before the ACK.  Without this
                    # the NULLs are mis-identified as case-3/4 command data.
                    while pb0 == 0x60:
                        pb0 = self.read_byte()
                    if (pb0 == bIns or pb0 == (bIns ^ 0xFF)):
                        # ACK (full match or ~INS): case 2/4 (response data
                        # follows).  Read exactly P3 response bytes, then
                        # SW1 SW2.  P3-bounded reads avoid the "read until
                        # SW" bug where FCP tag 0x62 is misidentified as
                        # SW1, truncating GET RESPONSE data.
                        for _ in range(p3):
                            packet.append(self.read_byte())
                        sw1 = self.read_byte()
                        packet.append(sw1)  # SW1
                        sw2 = self.read_byte()
                        packet.append(sw2)  # SW2
                        got_sw = True
                    else:
                        # Case 2/3/4: determine data direction from P3 and
                        # the first post-header byte.
                        packet.append(pb0)
                        if (p3 == 0):
                            # P3=0 (Le=0): no command data.  Card sends
                            # response data + SW, or SW directly (no ACK).
                            if ((pb0 & 0xF0) == 0x60
                                    or (pb0 & 0xF0) == 0x90):
                                # pb0 is SW1: card sent SW directly.
                                packet.append(self.read_byte())
                                got_sw = True
                            else:
                                # pb0 is response data: read until SW.
                                for _ in range(512):
                                    b = self.read_byte()
                                    packet.append(b)
                                    if ((b & 0xF0) == 0x60
                                            or (b & 0xF0) == 0x90):
                                        packet.append(self.read_byte())
                                        got_sw = True
                                        break
                        else:
                            # Case 3/4: P3 command-data bytes, then
                            # procedure byte.
                            for _ in range(max(p3 - 1, 0)):
                                packet.append(self.read_byte())
                            for _proc in range(32):
                                pb = self.read_byte()
                                if (pb == bIns or pb == (bIns ^ 0xFF)):
                                    # ACK (full match / ~INS): case 4 -> read response until SW.
                                    for _ in range(512):
                                        b = self.read_byte()
                                        packet.append(b)
                                        if ((b & 0xF0) == 0x60
                                                or (b & 0xF0) == 0x90):
                                            packet.append(self.read_byte())
                                            got_sw = True
                                            break
                                    break
                                elif (pb == (bIns ^ 0x01)
                                        or pb == ((bIns ^ 0xFF) ^ 0x01)):
                                    # Single-byte match (INS^0x01 / ~INS^0x01):
                                    # read 1 byte, continue handshake.
                                    packet.append(self.read_byte())
                                    continue
                                elif (pb == 0x60):
                                    # NULL: card busy; next procedure byte.
                                    continue
                                elif (pb == 0x9e or pb == 0x9f):
                                    # Extended-length procedure byte: L
                                    # response data bytes follow, then SW.
                                    L = self.read_byte()
                                    for _ in range(L):
                                        packet.append(self.read_byte())
                                    continue
                                elif ((pb & 0xF0) == 0x60
                                        or (pb & 0xF0) == 0x90):
                                    # SW1: case 3, no response data.
                                    packet.append(pb)
                                    packet.append(self.read_byte())
                                    got_sw = True
                                    break
                                else:
                                    # Unexpected byte: scan for SW.
                                    for _ in range(512):
                                        packet.append(pb)
                                        if ((pb & 0xF0) == 0x60
                                                or (pb & 0xF0) == 0x90):
                                            packet.append(self.read_byte())
                                            got_sw = True
                                            break
                                        pb = self.read_byte()
                                    break
                else:
                    # ATR-based captures (test_8 / test_7): keep the original
                    # procedure loop unchanged.
                    data_read = False
                    for _proc in range(8):
                        pb = self.read_byte()
                        if (pb == bIns or pb == (bIns ^ 0xFF)) and not data_read:
                            # ACK (full match / ~INS): the P3 bytes follow on
                            # the wire (Lc command data for case 3, Le response
                            # data for case 2).
                            data_read = True
                            for _ in range(p3):
                                packet.append(self.read_byte())
                        elif (pb == (bIns ^ 0x01)
                                or pb == ((bIns ^ 0xFF) ^ 0x01)):
                            # Single-byte match (INS^0x01 / ~INS^0x01):
                            # read 1 byte, continue handshake.
                            packet.append(self.read_byte())
                            continue
                        elif (pb == 0x60):
                            # NULL: card busy, wait for the next procedure byte.
                            pass
                        elif (pb == 0x9e or pb == 0x9f):
                            # T=0 extended-length procedure byte: the next byte
                            # L is the number of response data bytes the card
                            # now sends, followed by the status word.
                            L = self.read_byte()
                            for _ in range(L):
                                packet.append(self.read_byte())
                        elif ((pb & 0xF0) == 0x60 or (pb & 0xF0) == 0x90):
                            # SW1: append SW2; the exchange is complete.
                            packet.append(pb)
                            packet.append(self.read_byte())
                            got_sw = True
                            break
                        else:
                            # Mis-framed procedure byte: stop reading.  The
                            # partial packet is flagged desynced downstream and
                            # the decoder re-aligns on the next idle gap.
                            self.put(es, self.samplenum, self.out_ann,
                                     [0, ["INVALID Procedure Byte"]])
                            self.log("INVALID Procedure Byte", hex(pb))
                            self._resync = True
                            break
                self.put(es, self.samplenum, self.out_ann, [4, ["T=0"]])
                if (got_sw and len(packet) >= 7):
                    self.put(es, self.samplenum, self.out_ann, [9, ["APDU", "APDU cls={cls:02x} ins={ins:02x}".format(cls=bClass,ins=bIns), "APDU cls={cls:02x} ins={ins:02x} p1={p1:02x} p2={p2:02x} p3={p3:02x} len={len} status={sw1:02x}{sw2:02x}".format(cls=bClass,ins=bIns,p1=p1,p2=p2,p3=p3,len=p3,sw1=packet[-2],sw2=packet[-1])]])
            elif (self.hasT1):
                isIBlock,packet = self.t1_parse_block(es)
                if (isIBlock):
                    for _ in range(32):  # bounded chain follow-up
                        isIBlock,packet2 = self.t1_parse_block(es)
                        if (isIBlock):
                            packet = packet + packet2
                            break
                self.put(es, self.samplenum, self.out_ann, [4, ["T=1", "T=1 (reassembled)"]])
                if (len(packet) >= 8):
                    self.put(es, self.samplenum, self.out_ann, [9, ["APDU", "APDU cls={cls:02x} ins={ins:02x}".format(cls=packet[0],ins=packet[1]), "APDU cls={cls:02x} ins={ins:02x} p1={p1:02x} p2={p2:02x} p3={p3:02x} len={len} status={sw1:02x}{sw2:02x}".format(cls=packet[0],ins=packet[1],p1=packet[2],p2=packet[3],p3=packet[4],len=len(packet) - 7,sw1=packet[-2],sw2=packet[-1])]])


            if (len(packet) > 0):
                # All-zero first: an I/O-held-low stretch is idle noise,
                # not a TPDU -- suppress it entirely (and re-sync later).
                if (all(b == 0 for b in packet)):
                    self._idle_low += 1
                    if self._idle_low == 1 or self._idle_low % 256 == 0:
                        self.put(es, self.samplenum, self.out_ann,
                                 [Ann.ANN_WARN,
                                  ["line idle-low (all-zero reads suppressed)"]])
                    self._resync = True
                elif is_desynced(packet):
                    # Keep the bytes but flag them via GSMTAP_FLAG_BAD_FCS
                    # (res byte) so downstream tools can tell desynced
                    # TPDUs apart; sub_type stays 0x00.  Then re-align.
                    self.put(es, self.samplenum, self.out_ann,
                             [Ann.ANN_WARN,
                              ["desynced APDU (flagged BAD_FCS)"]])
                    self.emit_packet(GSMTAP_SIM_APDU, bytes(packet),
                                     es, self.samplenum,
                                     flags=GSMTAP_FLAG_BAD_FCS)
                    self._resync = True
                else:
                    self._idle_low = 0
                    self.emit_packet(GSMTAP_SIM_APDU, bytes(packet),
                                     es, self.samplenum)

            self.log("PACKETEND", codecs.encode(bytes(packet), 'hex'))
        else:
            return False
        return True

    def decode(self):
        try:
            self.write_pcap_header();
            failures = 0
            while True:
                # Crash protection: garbage from a noisy live signal must
                # never kill the whole sigrok-cli process.  Log, warn and
                # resync.  SystemError from wait() is the end-of-sample-
                # stream signal and must propagate for a clean exit;
                # KeyboardInterrupt (Ctrl+C) likewise passes through.
                try:
                    if (not self.decode_step()):
                        break
                    failures = 0
                except SystemError:
                    raise
                except Exception as e:
                    traceback.print_exc(file=sys.stderr)
                    self.log("DECODE ERROR:", repr(e), "- resyncing")
                    try:
                        wss = max(self.ss, 0)
                        wes = max(self.es, wss + 1)
                        self.put(wss, wes, self.out_ann,
                                 [Ann.ANN_WARN, ["decode error, resynced"]])
                    except Exception:
                        pass
                    self.state = 'DATA'
                    failures += 1
                    if (failures >= 50):
                        self.log("decode failed 50 times in a row, stopping")
                        break
        finally:
            self.finish();
