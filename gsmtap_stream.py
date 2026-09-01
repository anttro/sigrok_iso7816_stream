##
## GSMTAP live streaming for the ISO 7816 decoder.
##
## Sends decoded events as GSMTAP-SIM UDP packets, compatible with
## simtrace2-sniff, simtrace2-pysniff and the GSMTAP dissector in
## Wireshark.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##

import socket
import struct

GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN = 4           # in 32-bit words (16 bytes)
GSMTAP_TYPE_SIM = 0x04

# sub_type values.  0x00-0x03 follow libosmocore gsmtap.h,
# 0x10/0x11 are custom extensions (not in the spec).
GSMTAP_SIM_APDU = 0x00
GSMTAP_SIM_ATR = 0x01
GSMTAP_SIM_PPS = 0x02        # request + response combined (this decoder)
GSMTAP_SIM_RST_EVENT = 0x10  # payload: [direction, level, reserved]
GSMTAP_SIM_VCC_EVENT = 0x11  # payload: [direction, level, reserved]

# RST/VCC event payload bytes:
#   byte 0 (direction):
#     RST: 1 = reset asserted (high->low), 0 = reset deasserted (low->high)
#     VCC: 1 = power applied (low->high),  0 = power removed (high->low)
#   byte 1 (level): line level after the transition (0 = low, 1 = high)
#   byte 2: reserved (0x00)

GSMTAP_UDP_PORT = 4729

# libosmocore gsmtap.h: per-packet flags live in the header `res` byte.
GSMTAP_FLAG_BAD_FCS = 0x01  # "Any data checksum is wrong" -- reused here to
                            # mark decoder-desynced TPDUs (see SIGROK_ISO7816.md).

_HDR_FMT = '!BBBBHBBIBBBB'   # 16 bytes, big-endian


def build_packet(sub_type, data, flags=0):
    '''Build a complete GSMTAP packet (header + payload) as bytes.

    `flags` is written into the header `res` byte (GSMTAP_FLAG_*).'''
    hdr = struct.pack(
        _HDR_FMT,
        GSMTAP_VERSION,    # version
        GSMTAP_HDR_LEN,    # hdr_len (in 32-bit words)
        GSMTAP_TYPE_SIM,   # type
        0,                 # timeslot
        0,                 # arfcn
        0,                 # noise_db
        0,                 # signal_db
        0,                 # frame_number
        sub_type,          # sub_type
        0,                 # antenna_nr
        0,                 # sub_slot
        flags,             # res (GSMTAP_FLAG_*)
    )
    return hdr + bytes(data)


class GsmtapStreamSender:
    '''Fire-and-forget UDP sender.

    Never raises on send: with no listener present, datagrams are
    silently dropped by the OS (same behavior as simtrace2-sniff).
    '''

    def __init__(self, host='127.0.0.1', port=GSMTAP_UDP_PORT):
        self._addr = (host, int(port))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # UDP to localhost sendto is non-blocking anyway; make it explicit so
        # a full socket buffer can never stall the decode loop.
        self._sock.setblocking(False)

    def send(self, sub_type, data, flags=0):
        try:
            self._sock.sendto(build_packet(sub_type, data, flags),
                              self._addr)
        except OSError:
            pass

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass
