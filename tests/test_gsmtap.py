"""Unit tests for GSMTAP flag plumbing + decoder desync helpers.

pd.py imports the libsigrokdecode bindings, which are not always present
in a bare Python env, so we stub a minimal `sigrokdecode` module and load
the real pd.py / gsmtap_stream.py sources under the `iso7816` package
name (mirroring how libsigrokdecode loads a decoder directory).
"""

import collections
import importlib.util
import os
import sys
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_iso7816():
    # Minimal sigrokdecode stub.
    srd = types.ModuleType('sigrokdecode')
    srd.Decoder = type('Decoder', (object,), {})
    srd.SRD_CONF_SAMPLERATE = 'samplerate'
    srd.OUTPUT_PYTHON = 'python'
    srd.OUTPUT_ANN = 'ann'
    srd.OUTPUT_BINARY = 'binary'
    sys.modules.setdefault('sigrokdecode', srd)

    pkg = types.ModuleType('iso7816')
    pkg.__path__ = [REPO]
    sys.modules.setdefault('iso7816', pkg)

    def load(name, relpath):
        spec = importlib.util.spec_from_file_location(
            'iso7816.' + name, os.path.join(REPO, relpath))
        mod = importlib.util.module_from_spec(spec)
        sys.modules['iso7816.' + name] = mod
        spec.loader.exec_module(mod)
        return mod

    return load('gsmtap_stream', 'gsmtap_stream.py'), \
        load('pd', 'pd.py')


class TestGsmtapFlags(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def test_build_packet_plain_res_zero(self):
        p = self.gs.build_packet(0x00, b'\x80\xf2')
        self.assertEqual(p[12], 0x00)
        self.assertEqual(p[15], 0x00)

    def test_build_packet_bad_fcs_flag(self):
        p = self.gs.build_packet(0x00, b'\x80\xf2',
                                 flags=self.gs.GSMTAP_FLAG_BAD_FCS)
        self.assertEqual(p[12], 0x00)          # sub_type preserved
        self.assertEqual(p[15], 0x01)          # res = BAD_FCS

    def test_build_packet_payload_passthrough(self):
        data = b'\x00\xa4\x00\x04\x02'
        p = self.gs.build_packet(0x00, data)
        self.assertEqual(p[16:], data)

    def test_flag_constant_value(self):
        self.assertEqual(self.gs.GSMTAP_FLAG_BAD_FCS, 0x01)

    def test_pps_subtypes_are_standard(self):
        # PPS is emitted as the two standard GSMTAP-SIM subtypes
        # (libosmocore gsmtap.h), request and response as separate packets.
        self.assertEqual(self.gs.GSMTAP_SIM_PPS_REQ, 0x02)
        self.assertEqual(self.gs.GSMTAP_SIM_PPS_RSP, 0x03)


class TestDesyncHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def test_plausible_sw_accepts_valid_classes(self):
        # ISO 7816-3 §10.3.3 Table 11: SW1 is '6X' or '9X', except '60'
        # (the NULL procedure byte).
        for sw1 in list(range(0x61, 0x70)) + list(range(0x90, 0xA0)):
            self.assertTrue(self.pd.plausible_sw(sw1), hex(sw1))

    def test_plausible_sw_rejects_garbage(self):
        for sw1 in (0x00, 0x01, 0x3B, 0x3F, 0x5F, 0x60, 0x88, 0xA0, 0xFF):
            self.assertFalse(self.pd.plausible_sw(sw1), hex(sw1))

    def test_max_tpdu_len(self):
        self.assertEqual(self.pd.MAX_TPDU_LEN, 271)

    def test_is_desynced_clean_packets(self):
        # header(5) + SW1 SW2 (P3=0 direct status word)
        self.assertFalse(self.pd.is_desynced(b'\x00\xa4\x00\x04\x00\x90\x00'))
        # ACK-style GET RESPONSE (header + proc + payload + SW 9000)
        self.assertFalse(self.pd.is_desynced(
            b'\x00\xc0\x00\x00\x25\xc0\x62\x23\x90\x00'))

    def test_is_desynced_extended_channel_valid(self):
        # v1.9.3: higher logical channels and the UICC extended classes
        # are clean traffic, not desync.  0x44 = SELECT on channel 8,
        # 0x4F = SELECT on channel 19, 0xC0 = STATUS on channel 4
        # ('CX'), 0xE2 = STATUS on channel 6 with SM ('EX').
        for h in ('44a40004009000', '4fa40004009000',
                  'c0f20000009000', 'e2f20000009000'):
            with self.subTest(h=h):
                self.assertFalse(self.pd.is_desynced(bytes.fromhex(h)))

    def test_idle_noise_byte(self):
        # All-1s artifacts with dropped bits are idle noise (including
        # 0x6F/0x7F/0xAF, which are not valid classes) ...
        for b in (0x6f, 0x7f, 0xaf, 0xbf, 0xf7, 0xfc, 0xfd, 0xfe):
            with self.subTest(b=b):
                self.assertTrue(self.pd.is_idle_noise_byte(b))
        # ... but valid, bit-dense CLAs are command bytes: 0x5F/0xCF/
        # 0xE7/0xEB/0xED-0xEF must not be swallowed by the noise resync.
        for b in (0x5f, 0xcf, 0xe7, 0xeb, 0xed, 0xee, 0xef):
            with self.subTest(b=b):
                self.assertFalse(self.pd.is_idle_noise_byte(b))
        # A sparse invalid class is not "idle noise" either (it takes the
        # suspicious-CLA path).
        self.assertFalse(self.pd.is_idle_noise_byte(0x20))

    def test_is_desynced_null_sw1_is_invalid(self):
        # Regression (v1.9.1): the T=0 NULL byte 0x60 is not SW1.  The
        # wire "NULL 0x60 + real SW1 0x61" was mis-framed as the status
        # word "60 61" (real SW1 eaten as SW2).  It must be flagged, not
        # accepted (trace: SELECT MF -> NULL wait -> 61 29).
        pkt = b'\x00\xa4\x00\x04\x02\x3f\x00\x60\x61'
        valid, reason = self.pd.validate_t0_apdu(pkt)
        self.assertFalse(valid, 'NULL must not pass as SW1')
        self.assertIn('invalid SW1', reason)
        self.assertTrue(self.pd.is_desynced(pkt))

    def test_is_desynced_short_fragment(self):
        # 5-byte header-only (INVALID-procedure residue) -- no SW read
        self.assertTrue(self.pd.is_desynced(b'\xa4\x3f\x00\x61\x25'))

    def test_is_desynced_bad_sw(self):
        self.assertTrue(self.pd.is_desynced(
            b'\x00\xa4\x00\x04\x02\x3f\x00\x00\xff'))

    def test_is_desynced_oversized(self):
        big = bytes([0x00, 0xb2, 0x00, 0x00, 0xff]) + b'\x00' * 300
        self.assertTrue(self.pd.is_desynced(big))

    def test_is_desynced_all_zero_is_not_desync(self):
        # all-zero is idle-low (suppressed), not desync
        self.assertFalse(self.pd.is_desynced(b'\x00' * 7))


    def test_resync_idle_waits_on_a_level_condition(self):
        # The re-align must WAIT for DATA (a level condition that advances
        # the sample counter).  It used to call wait({'skip': 0}) in a loop,
        # which never advanced -- a no-op repeated on the same sample.
        inst = object.__new__(self.pd.Decoder)
        inst.reset()
        inst.bit_samples = 100
        inst._inverse_convention = False  # normally set by start()
        inst._start_fall = None
        inst.samplenum = 0
        levels = [0, 0, 1]
        calls = []

        def wait(cond):
            calls.append(cond)
            want = None
            if isinstance(cond, list):
                for c in cond:
                    if self.pd.Decoder.DATA_IDX in c:
                        want = c[self.pd.Decoder.DATA_IDX]
            while levels:
                inst.samplenum += 10
                lvl = levels.pop(0)
                if (want == 'h' and lvl == 1) or (want == 'l' and lvl == 0):
                    return [lvl] * 8
            inst.samplenum += 10
            return [1] * 8

        inst.wait = wait
        inst.resync_idle()
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(calls[0], list)
        self.assertIn(self.pd.Decoder.DATA_IDX, calls[0][0])
        # it advanced through the two LOW samples to the HIGH one
        self.assertEqual(inst.samplenum, 30)


class TestEtuCandidate(unittest.TestCase):
    """The mid-session ETU estimator's burst validation (_etu_candidate)."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def setUp(self):
        self.inst = object.__new__(self.pd.Decoder)

    def test_zero_run_guard_is_rejected(self):
        # All-zero characters: 10-ETU LOW runs + a short HIGH inter-byte
        # guard.  The smallest recurring spacing is the guard, not the ETU.
        pairs = [(1000, 0), (200, 1)] * 8
        etu, ok = self.inst._etu_candidate(pairs)
        self.assertEqual(etu, 200)
        self.assertFalse(ok)

    def test_single_spacing_is_rejected(self):
        # A lone 0x00 character yields one 10-ETU run (10x the true ETU).
        self.assertEqual(self.inst._etu_candidate([(1000, 0)]),
                         (None, False))
        self.assertEqual(self.inst._etu_candidate([(8, 0)]),
                         (None, False))

    def test_normal_burst_is_accepted(self):
        # A 1-ETU LOW spacing (start bit / data run) alongside 2- and
        # 3-ETU runs: the recurring minimum is the true ETU.
        pairs = [(100, 0), (100, 1), (200, 0), (300, 1),
                 (100, 0), (100, 1), (200, 0)]
        etu, ok = self.inst._etu_candidate(pairs)
        self.assertEqual(etu, 100)
        self.assertTrue(ok)

    def test_ff_burst_is_accepted(self):
        # 0xFF: 1-ETU LOW start pulses + long HIGH runs.  The minimum is a
        # LOW run (the start bit), so the guard heuristic must not fire.
        pairs = [(100, 0), (900, 1), (100, 0), (900, 1), (100, 0)]
        etu, ok = self.inst._etu_candidate(pairs)
        self.assertEqual(etu, 100)
        self.assertTrue(ok)


class TestInverseConvention(unittest.TestCase):
    """ISO 7816-3 7.1: inverse = inverted data, msb first; the start bit
    stays a falling edge from an idle-HIGH line (the old code assumed an
    idle-LOW line / rising start)."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def setUp(self):
        self.inst = object.__new__(self.pd.Decoder)
        self.inst.reset()

    def test_get_bytes_direct_lsb_first(self):
        self.inst._inverse_convention = False
        self.assertEqual(self.inst.get_bytes([1, 0, 0, 0, 0, 0, 0, 0]), 0x01)
        self.assertEqual(self.inst.get_bytes([1, 1, 0, 0, 0, 0, 0, 0]), 0x03)

    def test_get_bytes_inverse_msb_first(self):
        self.inst._inverse_convention = True
        self.assertEqual(self.inst.get_bytes([1, 0, 0, 0, 0, 0, 0, 0]), 0x80)
        self.assertEqual(self.inst.get_bytes([1, 1, 0, 0, 0, 0, 0, 0]), 0xC0)

    def test_ts_from_bits_direct_inverse_and_garbage(self):
        self.assertEqual(
            self.pd.ts_from_bits([0, 1, 1, 0, 1, 1, 1, 0, 0, 1]), 0x3b)
        self.assertEqual(
            self.pd.ts_from_bits([0, 1, 1, 0, 0, 0, 0, 0, 0, 1]), 0x3f)
        self.assertIsNone(
            self.pd.ts_from_bits([0, 1, 1, 0, 1, 0, 1, 0, 0, 1]))
        self.assertIsNone(self.pd.ts_from_bits([0, 1, 1, 0]))

    def test_wait_data_falling_uses_high_idle_and_falling_start(self):
        self.inst._inverse_convention = True
        self.inst.bit_samples = 100
        self.inst._min_pulse_samples = 0
        self.inst.samplenum = 0
        conds = []

        def wait(cond):
            conds.append(cond)
            self.inst.samplenum += 200
            return [1] * 8 if len(conds) == 1 else [0] * 8

        self.inst.wait = wait
        self.inst.wait_data_falling()
        self.assertFalse(self.inst._eof)
        self.assertEqual(conds[0][0][self.pd.Decoder.DATA_IDX], 'h')
        self.assertEqual(conds[1][0][self.pd.Decoder.DATA_IDX], 'f')
        self.assertEqual(self.inst._start_fall, self.inst.samplenum)


class TestT1Blocks(unittest.TestCase):
    """T=1 block parsing: NAD/PCB/LEN/INF/LRC, the M-bit chain, and the
    EOF guards (a truncated block never raises or emits a half INF)."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def _make(self, byte_seq):
        inst = object.__new__(self.pd.Decoder)
        inst.reset()
        inst.samplenum = 0
        inst.out_ann = 0
        inst.log = lambda *a, **k: None
        inst.put = lambda *a, **k: None
        inst.wait = lambda cond=None: [1] * 8
        inst._bytes = collections.deque(byte_seq)
        inst.read_byte = lambda: (inst._bytes.popleft()
                                  if inst._bytes else None)
        return inst

    def _block(self, nad, pcb, inf):
        body = [nad, pcb, len(inf)] + list(inf)
        lrc = 0
        for b in body:
            lrc ^= b
        return body + [lrc]

    def test_i_block(self):
        inst = self._make(self._block(0x00, 0x00, [0x6f, 0x00]))
        self.assertEqual(inst.t1_parse_block(0), (True, [0x6f, 0x00]))

    def test_r_and_s_blocks_have_no_inf(self):
        inst = self._make(self._block(0x00, 0x80, []))
        self.assertEqual(inst.t1_parse_block(0), (False, []))
        inst = self._make(self._block(0x00, 0xc0, []))
        self.assertEqual(inst.t1_parse_block(0), (False, []))

    def test_m_chain_concatenates_inf(self):
        seq = (self._block(0x00, 0x20, [0x01])
               + self._block(0x00, 0x00, [0x02]))
        inst = self._make(seq)
        self.assertEqual(inst.t1_parse_block(0), (True, [0x01, 0x02]))

    def test_truncated_block_before_lrc_is_clean(self):
        seq = self._block(0x00, 0x00, [0x6f, 0x00])[:5]  # no LRC
        inst = self._make(seq)
        self.assertEqual(inst.t1_parse_block(0), (False, []))

    def test_truncated_inf_is_clean(self):
        inst = self._make([0x00, 0x00, 0x05, 0x01, 0x02])
        self.assertEqual(inst.t1_parse_block(0), (False, []))

    def test_decode_step_reads_exactly_one_block(self):
        # The T=1 caller used to run an extra chain loop after every
        # I-block: it consumed the peer's R-block and merged the following
        # I-block's INF into this packet.  One step must parse one block.
        apdu = [0x00, 0xa4, 0x00, 0x00, 0x00]
        rblock = self._block(0x00, 0x80, [])
        inst = self._make(self._block(0x00, 0x00, apdu) + rblock)
        inst.state = 'DATA'
        inst.hasT0 = False
        inst.hasT1 = True
        inst.bit_samples = 100
        inst._pps_speed_changed = False
        inst._resync = False
        inst._at_eof = lambda: False
        inst.out_ann = 0
        inst.emitted = []
        inst.emit_packet = lambda st, pl, ss, es, flags=0: \
            inst.emitted.append((bytes(pl), flags))
        inst._note_discard = lambda *a, **k: None
        inst._note_pre_sw = lambda *a, **k: None
        inst._consume_first = lambda: (inst._bytes.popleft()
                                       if inst._bytes else None)
        inst.peek_byte = lambda: inst._bytes[0] if inst._bytes else None
        self.assertTrue(inst.decode_step())
        self.assertEqual(len(inst.emitted), 1)
        self.assertEqual(inst.emitted[0][0], bytes(apdu))
        # The peer's R-block is left for the next step.
        self.assertEqual(list(inst._bytes), rblock)

    def test_handle_pps_truncated_is_clean(self):
        inst = self._make([0x55])
        inst.peeked_samplenum = 0
        inst.handle_pps()  # pps0 missing: must not raise

    def test_handle_pps_truncated_optional_is_clean(self):
        inst = self._make([0x55, 0x70])  # PPS0 asks for PPS1..3, then EOF
        inst.peeked_samplenum = 0
        inst.handle_pps()  # PPS1 missing: must not raise


class TestSamplerateScaling(unittest.TestCase):
    """The pulse/glitch thresholds scale with the capture rate instead of
    assuming 16 MHz."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def test_samples_for_us(self):
        inst = object.__new__(self.pd.Decoder)
        inst.samplerate = 16000000
        self.assertEqual(inst._samples_for_us(0.125), 2)
        self.assertEqual(inst._samples_for_us(0.25), 4)
        self.assertEqual(inst._samples_for_us(0.75), 12)
        inst.samplerate = 96000000
        self.assertEqual(inst._samples_for_us(0.125), 12)
        self.assertEqual(inst._samples_for_us(0.75), 72)
        inst.samplerate = None
        self.assertEqual(inst._samples_for_us(0.75), 12)  # 16 MHz fallback

    def test_etu_glitch_floor_scales(self):
        inst = object.__new__(self.pd.Decoder)
        inst.samplerate = 96000000
        # 12-sample spacings are sub-ETU glitches at 96 MHz (floor 72).
        self.assertEqual(inst._etu_candidate([(12, 0), (12, 1)]),
                         (None, False))
        inst.samplerate = 16000000
        self.assertEqual(inst._etu_candidate([(12, 0), (12, 1)]),
                         (12, True))


class TestValidateT0Apdu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def _valid(self, packet):
        valid, reason = self.pd.validate_t0_apdu(packet)
        self.assertTrue(valid, 'expected valid, got: ' + str(reason))

    def _invalid(self, packet, expected_reason_substring=None):
        valid, reason = self.pd.validate_t0_apdu(packet)
        self.assertFalse(valid, 'expected invalid')
        if expected_reason_substring:
            self.assertIn(expected_reason_substring, reason)

    def test_valid_case1_direct_sw(self):
        # P3=0, 7 bytes, direct SW
        self._valid(b'\x00\xa4\x00\x04\x00\x90\x00')

    def test_valid_direct_sw_with_p3_nonzero(self):
        # Card can reject a command and send SW immediately, even with P3>0
        self._valid(b'\x00\xa4\x00\x04\x02\x90\x00')

    def test_valid_case2_with_response(self):
        # header(5) + 2 response bytes + SW(2)
        self._valid(b'\x00\xb0\x00\x00\x02\x12\x34\x90\x00')

    def test_valid_case3_with_command_data(self):
        # header(5) + 4 command bytes + SW(2)
        self._valid(b'\x00\xd6\x00\x00\x04\x11\x22\x33\x44\x90\x00')

    def test_valid_cla_interindustry_classes(self):
        # Interindustry CLA (ISO 7816-4 §5.1.1): 000x xxxx 0x00-0x1F
        # (channels 0-3 in b2b1, SM 0x0C, chaining 0x10-0x1F) and
        # 01xx xxxx 0x40-0x5F (channels 4-19 without CLA-level SM:
        # b4..b1 = channel-4).  0x20-0x3F is reserved by ISO; the
        # SM-indicating 0x60-0x6F/0x70-0x7F stay rejected -- see
        # test_invalid_cla_untraced_variants.
        for cla in (0x01, 0x02, 0x03, 0x0C, 0x10, 0x14,
                    0x40, 0x44, 0x4F, 0x50, 0x54):
            pkt = bytes([cla, 0xa4, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(cla=cla):
                self._valid(pkt)

    def test_valid_cla_uicc_classes(self):
        # UICC extended classes (TS 102 221 §10.1.1 Table 10.4a): 'CX'/'EX'
        # (0xC0-0xCF/0xE0-0xEF) carry the extended channels 4-19 in b4..b1
        # (SM in b6).  The legacy SIM/UICC values and 0xB0 (no pinned-spec
        # basis, kept for compatibility) are unchanged.
        for cla in (0x80, 0x84, 0xA0, 0xB0,
                    0xC0, 0xC4, 0xCF, 0xE0, 0xE4, 0xEF):
            pkt = bytes([cla, 0xa4, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(cla=cla):
                self._valid(pkt)

    def test_valid_cla_extended_channel_exchanges(self):
        # Real higher-channel shapes from TS 102 221 Tables 10.4a/10.5:
        # SELECT on channel 8 ('4X'), SELECT on channel 19 ('4X'),
        # STATUS on channel 4 ('CX'), STATUS on channel 6 with SM
        # ('EX' -- the UICC extended class accepts b6 = SM).
        self._valid(b'\x44\xa4\x00\x04\x00\x90\x00')
        self._valid(b'\x4f\xa4\x00\x04\x00\x90\x00')
        self._valid(b'\xc0\xf2\x00\x00\x00\x90\x00')
        self._valid(b'\xe2\xf2\x00\x00\x00\x90\x00')

    def test_valid_cla_channel1_select_after_manage_channel(self):
        # The command that follows MANAGE CHANNEL (00 70 00 00 01) opening
        # logical channel 1 legitimately uses CLA 0x01.  This exact type
        # (SELECT by AID) is what the A55/S21p traces carry.
        self._valid(b'\x01\xa4\x00\x04\x0c'
                    b'\xa0\x00\x00\x00\x63\x50\x4b\x43\x53\x2d\x31\x35'
                    b'\x6a\x82')

    def test_invalid_cla_reserved_and_unseen(self):
        # 0x20-0x3F (001x xxxx) is reserved by ISO 7816-4; 0x90-0x9F,
        # 0xD0-0xDF and 0xF0-0xFF are not SIM/UICC classes ('11x0' needs
        # b5 = 0).  All stay invalid.
        for cla in (0x20, 0x2F, 0x3F, 0x90, 0x9F, 0xD0, 0xDF, 0xF0, 0xFE):
            pkt = bytes([cla, 0xa4, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(cla=cla):
                self._invalid(pkt, 'invalid CLA')

    def test_invalid_cla_untraced_variants(self):
        # Accepted-set precision (v1.9.3): the higher-channel codings that
        # cost frame-start precision stay rejected.  0x60-0x6F/0x70-0x7F
        # are the SM-indicating extended classes -- 0x60-0x6F overlaps
        # printable ASCII ('a'-'o'), and the text byte 0x61 started a bogus
        # frame on xiaomi_mi_a1_coldboot; 0x81-0x83/0x85-0x8F/0xA1-0xAF
        # are the '8X'/'AX' standard-channel variants (channels 0-3) other
        # than the legacy 0x80/0x84/0xA0, where the FCP byte 0xA5 did the
        # same.
        for cla in (0x60, 0x61, 0x6F, 0x70, 0x73, 0x7F,
                    0x81, 0x85, 0x8F, 0xA1, 0xA5, 0xAF):
            pkt = bytes([cla, 0xa4, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(cla=cla):
                self._invalid(pkt, 'invalid CLA')

    def test_odd_ins_set_pinned(self):
        # Exactly the odd codes the pinned specs define: the ISO 7816-4
        # Table 4 pairs (0F ERASE BINARY, 21 VERIFY, 87 GENERAL
        # AUTHENTICATE, A1 SEARCH BINARY, B1 READ BINARY, B3 READ RECORD,
        # C3 ENVELOPE, CB GET DATA, D1 WRITE BINARY, D7 UPDATE BINARY,
        # DB PUT DATA, DD UPDATE RECORD), TS 102 221 AUTHENTICATE 89, and
        # TS 102 221 Table 10.5 MANAGE SECURE CHANNEL 73 / TRANSACT DATA 75
        # (the v1.9.6 audit found these two missing).
        self.assertEqual(self.pd.ODD_INS, frozenset((
            0x0F, 0x21, 0x73, 0x75, 0x87, 0x89, 0xA1, 0xB1, 0xB3,
            0xC3, 0xCB, 0xDB, 0xD1, 0xD7, 0xDD)))
        for ins in (0x73, 0x75):
            with self.subTest(ins=ins):
                self.assertTrue(self.pd.plausible_ins(ins))

    def test_vs_reader_mirror(self):
        # tools/vs_reader.py duplicates the acceptance predicates for its
        # standalone pcap analysis; the copies must not drift from pd.py
        # (a drift would make its "suspicious CLA" / validity metrics and
        # the --pcap-only verdict disagree with the decoder).
        path = os.path.join(REPO, 'tools', 'vs_reader.py')
        spec = importlib.util.spec_from_file_location('vs_reader', path)
        vs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vs)
        self.assertEqual(
            vs.VALID_CLA,
            frozenset(c for c in range(256) if self.pd.plausible_cla(c)))
        self.assertEqual(vs.ODD_INS, self.pd.ODD_INS)
        self.assertEqual(vs.EMBEDDED_CLA, self.pd.EMBEDDED_CLA)

    def test_invalid_too_short(self):
        self._invalid(b'\x00\xa4\x00\x04\x00\x90', 'too short')

    def test_invalid_cla(self):
        self._invalid(b'\xff\xa4\x00\x04\x00\x90\x00', 'invalid CLA')

    def test_invalid_ins_zero(self):
        self._invalid(b'\x00\x00\x00\x04\x00\x90\x00', 'invalid INS')

    def test_valid_ins_odd_variants(self):
        # Odd INS codes are accepted as the defined alternate variants:
        # ISO 7816-4 Table 4 pairs (READ BINARY 'B1', ENVELOPE 'C3',
        # UPDATE RECORD 'DD', ...) and TS 102 221 AUTHENTICATE '89'.
        for ins in (0x0F, 0x21, 0x87, 0x89, 0xA1, 0xB1, 0xB3,
                    0xC3, 0xCB, 0xD1, 0xD7, 0xDB, 0xDD):
            pkt = bytes([0x00, ins, 0x00, 0x00, 0x00, 0x90, 0x00])
            with self.subTest(ins=ins):
                self._valid(pkt)

    def test_invalid_ins_odd_undefined(self):
        # Odd INS values with no defined command stay rejected: a
        # mis-framed boundary exposes data bytes, and the text run
        # "I M" (0x49 0x4D) started a bogus frame on xiaomi_phone_sample
        # when every odd INS was accepted.
        for ins in (0x03, 0x4D, 0x4F, 0xA5, 0xD3):
            pkt = bytes([0x00, ins, 0x00, 0x00, 0x00, 0x90, 0x00])
            with self.subTest(ins=ins):
                self._invalid(pkt, 'invalid INS')

    def test_invalid_ins_sw_collision(self):
        for ins in (0x64, 0x9F):
            pkt = bytes([0x00, ins, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(ins=ins):
                self._invalid(pkt, 'invalid INS')

    def test_invalid_sw1(self):
        self._invalid(b'\x00\xa4\x00\x04\x00\xff\x00', 'invalid SW1')

    def test_invalid_oversized(self):
        big = bytes([0x00, 0xb2, 0x00, 0x00, 0xff]) + b'\x00' * 300
        self._invalid(big, 'exceeds T=0 max length')


class TestNextStartFall(unittest.TestCase):
    def setUp(self):
        _, pd = _load_iso7816()
        # _next_start_fall is an instance method but does not use self.
        self.inst = object.__new__(pd.Decoder)

    def test_finds_fall_after_threshold(self):
        edges = [(100, 0), (200, 1), (300, 0)]
        self.assertEqual(self.inst._next_start_fall(edges, 250, 100), 300)

    def test_finds_fall_exactly_at_threshold(self):
        """Regression test for Samsung 16 CLK/ETU concatenation.

        When the next byte's start-bit fall lands exactly on the
        ``10 * bs`` boundary, the previous strict ``>`` test missed it.
        """
        edges = [(100, 0), (200, 1), (300, 0)]
        self.assertEqual(self.inst._next_start_fall(edges, 300, 100), 300)

    def test_returns_none_when_no_fall(self):
        edges = [(100, 0), (200, 1)]
        self.assertIsNone(self.inst._next_start_fall(edges, 300, 100))

    def test_rejects_phantom_sub_etu_fall(self):
        # A sub-ETU low bounce in the stop/guard time (fall at 290, quick
        # rise at 310) must NOT be accepted as the next start; the scan
        # skips it and only accepts the genuine start fall at 400.
        edges = [(100, 0), (290, 0), (310, 1), (400, 0)]
        self.assertEqual(self.inst._next_start_fall(edges, 250, 100), 400)

    def test_accepts_full_hold_fall(self):
        # Genuine start fall: held LOW for a full ETU before the rise.
        edges = [(100, 0), (300, 0), (400, 1)]
        self.assertEqual(self.inst._next_start_fall(edges, 250, 100), 300)


class TestDeglitchEdges(unittest.TestCase):
    def setUp(self):
        _, pd = _load_iso7816()
        self.inst = object.__new__(pd.Decoder)

    def test_no_edges(self):
        self.assertEqual(self.inst._deglitch_edges([], 72), [])

    def test_glitch_low_pulse_removed(self):
        # Real start fall at 0, real rise at 72, 1-sample LOW glitch
        # at 73-74, real fall at 144 (next byte start). bs=72, threshold=14.
        edges = [(0, 0), (72, 1), (73, 0), (74, 1), (144, 0)]
        # After removing the 1-sample LOW pulse (73,0)-(74,1),
        # the line stays HIGH until the next real edge.
        result = self.inst._deglitch_edges(edges, 72)
        self.assertEqual(result, [(0, 0), (72, 1), (144, 0)])

    def test_real_pulses_preserved(self):
        # 72-sample real LOW pulse; should not be touched.
        edges = [(0, 0), (72, 1), (144, 0), (216, 1)]
        result = self.inst._deglitch_edges(edges, 72)
        self.assertEqual(result, edges)

    def test_short_pulse_start_edge_preserved(self):
        # Pulse starting at the first edge: start-bit fall is preserved,
        # only the edge ending the short pulse is removed.
        edges = [(0, 0), (1, 1), (100, 0)]
        result = self.inst._deglitch_edges(edges, 72)
        self.assertEqual(result, [(0, 0), (100, 0)])


class TestAtrHuntEscape(unittest.TestCase):
    """Regression: the ATR hunt must never loop forever on an idle/unsyncable
    line, and must recover the live ETU when the card is already at a
    non-default F/D (Samsung 16 CLK/bit) with no 372-rate ATR coming."""

    def setUp(self):
        _, pd = _load_iso7816()
        self.pd = pd
        self.inst = object.__new__(pd.Decoder)
        self.inst.bit_samples = None
        self.inst._etu_measured = False
        self.inst._atr_hunt_count = 0
        self.inst._atr_fail_total = 0
        self.inst._hunt_etu_attempts = 0
        self.inst._atr_idle_resets = 0

    def _hunt_round(self, byte):
        """Mirror handle_atr's bookkeeping around _atr_hunt_failure_action."""
        self.inst._atr_hunt_count += 1
        action = self.inst._atr_hunt_failure_action(byte)
        if action == 'recover':
            self.inst._atr_hunt_count = 0
        elif action == 'retry' and byte == 0xFF:
            self.inst._atr_idle_resets += 1
            self.inst._atr_hunt_count = 0
        return action

    def test_retry_then_recover_after_two_failures(self):
        self.assertEqual(self._hunt_round(0x00), 'retry')
        self.assertEqual(self._hunt_round(0x00), 'recover')
        self.assertEqual(self.inst._hunt_etu_attempts, 1)

    def test_seeded_bit_samples_does_not_block_recovery(self):
        # handle_atr pre-seeds bit_samples with the default-rate guess; the
        # recovery must key off a real DATA measurement, not on bit_samples
        # being None (the pre-seed used to defeat the v1.6.0 recovery).
        self.inst.bit_samples = 1488
        self.inst._etu_measured = False
        self.assertEqual(self._hunt_round(0x00), 'retry')
        self.assertEqual(self._hunt_round(0x00), 'recover')

    def test_measured_etu_skips_recovery(self):
        # A real measurement means the rate is known: no re-measurement.
        self.inst.bit_samples = 1488
        self.inst._etu_measured = True
        actions = [self._hunt_round(0x00) for _ in range(6)]
        self.assertNotIn('recover', actions)

    def test_recovery_attempts_capped_then_hard_limit(self):
        actions = [self._hunt_round(0x00) for _ in range(200)]
        actions = actions[:actions.index('resume_data') + 1]
        self.assertEqual(actions.count('recover'),
                         self.pd.ATR_HUNT_ETU_ATTEMPTS)
        self.assertEqual(actions[-1], 'resume_data')

    def test_all_ff_idle_loop_is_bounded(self):
        seen = []
        for _ in range(200):
            seen.append(self._hunt_round(0xFF))
            if seen[-1] == 'resume_data':
                break
        self.assertEqual(seen[-1], 'resume_data')
        self.assertLess(len(seen), 20)

    def test_idle_ff_retries_before_cap(self):
        self.inst.bit_samples = 100  # ETU known -> recovery disabled
        self.inst._hunt_etu_attempts = self.pd.ATR_HUNT_ETU_ATTEMPTS
        self.inst._atr_idle_resets = self.pd.ATR_HUNT_IDLE_RESETS - 1
        self.assertEqual(self.inst._atr_hunt_failure_action(0xFF), 'retry')

    def test_idle_resets_capped_then_resume(self):
        self.inst.bit_samples = 100
        self.inst._hunt_etu_attempts = self.pd.ATR_HUNT_ETU_ATTEMPTS
        self.inst._atr_idle_resets = self.pd.ATR_HUNT_IDLE_RESETS
        self.assertEqual(self.inst._atr_hunt_failure_action(0xFF),
                         'resume_data')

    def test_non_ff_resumes_when_count_high(self):
        self.inst.bit_samples = 100
        self.inst._hunt_etu_attempts = self.pd.ATR_HUNT_ETU_ATTEMPTS
        self.inst._atr_hunt_count = 8
        self.assertEqual(self.inst._atr_hunt_failure_action(0x00),
                         'resume_data')

    def test_no_recovery_when_etu_known(self):
        self.inst.bit_samples = 100
        self.inst._etu_measured = True
        for _ in range(6):
            self.assertEqual(self._hunt_round(0x00), 'retry')
        self.assertEqual(self.inst._hunt_etu_attempts, 0)

    def test_recover_etu_in_hunt_runs_measurement(self):
        calls = []
        self.inst._samples_per_clock = 4.0  # skip CLK-period measurement
        self.inst._measure_etu = lambda: calls.append('measure')
        self.inst._derive_clock_skip_from_etu = lambda: calls.append('derive')
        self.inst._measure_clock_period = lambda: calls.append('period')
        self.inst.log = lambda *a, **k: None
        self.inst.clock_skip = 372
        self.inst._atr_hunt_count = 5
        self.inst._recover_etu_in_hunt()
        self.assertEqual(calls, ['measure', 'derive'])
        self.assertEqual(self.inst._atr_hunt_count, 0)


class TestEmbeddedExchanges(unittest.TestCase):
    """CONCAT detection: structurally valid packets that embed complete T=0
    exchanges (a byte-drop mis-frame swallowed several real exchanges into
    one APDU).  Vectors are exact bytes from the 10-trace suite."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def _hits(self, hexstr):
        return self.pd.embedded_exchanges(bytes.fromhex(hexstr))

    def test_clean_get_response_fcp(self):
        # FCP response with 0x62/0x6f BER-TLV tags + p1=f0 PIN template;
        # classic false-positive candidate -- must NOT hit.
        h = ('00c000001ec0621c8202412183026f43a503920100'
             '8a01058b032f0604800200028800913e')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [])

    def test_clean_select_611e(self):
        # Plain SELECT -> 611E (test_8/7 session) must not hit.
        self.assertEqual(self._hits('00a4080404a47fff611e'), [])

    def test_clean_select_6a82(self):
        self.assertEqual(self._hits('00a4080404a47fff6a82'), [])

    def test_clean_read_record_ff_run(self):
        # READ RECORD whose response is an all-FF fill run + 9000.  The FF
        # data must not be mistaken for embedded headers.
        h = '00b2020440' + 'ff' * 64 + '9000'
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [])

    def test_clean_channel1_select_after_manage_channel(self):
        # A properly decoded post-MANAGE-CHANNEL exchange (CLA 0x01,
        # SELECT by AID, 6A 82) is a CLEAN single exchange: it must
        # validate and must NOT be flagged as CONCAT.
        h = ('01a400040ca000000063504b43532d31356a82')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [])
        self.assertFalse(self.pd.is_desynced(bytes.fromhex(h)))

    def test_clean_atr_fragment_select(self):
        # ATR-recovery fragment (header + 3F 00 + 6125) must not hit.
        self.assertEqual(self._hits('00a40004023f006125'), [])

    def test_clean_secured_packet_payload_alcor(self):
        # alcor_reader[46] (n=87): GET RESPONSE whose 80-byte payload holds a
        # secured-packet run "40 70 70 61 15" 21 bytes before an SW-like byte;
        # the reader follows with 00 c0 00 00 19 -- a clean single exchange.
        # The extended-channel 0x4x CLA must not turn payload bytes into a
        # hit: the CONCAT detector is deliberately blind to those classes.
        h = ('80c2000050d14e82028381060291978b4440048111227ff64070706115'
             '3500350270000030151601252500000018ed15e8476126aa9cacbbe8f4'
             '735f962016e3c6e30a26af20c02bad2a34bdf49f152e263bc7390a6119')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [])

    def test_embedded_cla_membership_pinned(self):
        # CONCAT precision (v1.9.3): the detector's CLA set is deliberately
        # NARROWER than plausible_cla() -- it must not follow the widened
        # acceptance into the extended-channel classes (0x40-0x7F,
        # 0xC0-0xEF) that false-hit on payload bytes (the Alcor vector
        # above).  Pin the exact membership.
        expected = frozenset(list(range(0x00, 0x20)) +
                             [0x80, 0x84, 0xA0, 0xB0])
        self.assertEqual(self.pd.EMBEDDED_CLA, expected)

    def test_a55_u1_concat(self):
        # A55[296] (n=70): phantom-00 (buffer {01}) CLA + slip prefix.
        h = ('000402a43f00612501c0000025c062238202782183023f00a5098001'
             '7183040000eec18a01058b032f0601c6069001008301019000'
             '01a4000402a42f00612101c0000021621f')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [(8, 51), (53, 61)])

    def test_a55_u4_mega_concat(self):
        # A55[281] (n=167): the CAT ENVELOPE mega-concat (7 embedded).
        h = ('04040ca4a000000063504b43532d31356a8280f2000c009000007080'
             '0100900000a4000c02a43f009000801400000c148103012500020282'
             '81830100910f801200000f12d00d8103010500820281829902031290'
             '0000a4000c02a43f009000801400000c148103010500020282818301'
             '00910f801200000f12d00d8103010300820281828402011e90008014'
             '000010148103010300020282818301000402011e90000070009000')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        hits = self._hits(h)
        self.assertEqual(len(hits), 7)
        self.assertEqual(hits[0], (32, 40))

    def test_samsung_record_burst_concat(self):
        # samsung_phone[826] (n=247): mis-framed READ RECORD chain.
        h = ('0408b252f0990000fffe01900000b2020408b252f0430000fffe02900'
             '000b2030408b252f0230000fffe03900000b2040408b252f0450000f'
             'ffe02900000b2050408b252f0490000fffe04900000b2060408b252f'
             '0690000fffe05900000b2070408b252f0790000fffe06900000b2080'
             '408b252f0890000fffe07900000b2090408b2ffffffffffffffff900'
             '000b20a0408b2ffffffffffffffff900000a4000402a46f40611b00c'
             '000001bc0621982054221001c0283026f408a01058b036f060980020'
             '0388800900000b201041cb2fffffffffbfbfbfbfbfbfbfbfbfbfbfbf'
             'bfbfbfbfbfbfbfbfb830300b202041cb2ffff9000')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(len(self._hits(h)), 15)

    def test_xiaomi_select_getresp_swallow(self):
        # xiaomi[613] (n=118): stacked SELECT/GET RESPONSE exchanges.
        h = ('04a47fff6f116a8200a4080404a47fff6fe3611e00c000001ec0621c'
             '8202412183026fe3a503c001808a01058b036f0609800200128801f0'
             '900000a4080404a47fff6f136a8200a4080404a47fff6fe3611e00c0'
             '00001ec0621c8202412183026fe3a503c001808a01058b036f060980'
             '020012889000')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(len(self._hits(h)), 4)

    def test_channel1_select_after_manage_channel_swallow(self):
        # Channels: MC opens channel 1 (00 70 00 00 01 -> 01 90 00: the 01
        # response byte is the opened channel number), then a channel-1
        # SELECT-by-AID (01 A4 00 04 0C AID -> 6A 82) that a mis-frame
        # swallowed into the MC packet.  The embedded exchange starts on
        # CLA 0x01 -- a real channel-1 cluster byte, not a phantom: the
        # detector must find it.
        h = ('007000000101900001a400040ca000000063504b43532d31356a829000')
        self.assertTrue(self.pd.validate_t0_apdu(bytes.fromhex(h))[0])
        self.assertEqual(self._hits(h), [(8, 25)])

    def test_concat_packets_are_not_is_desynced(self):
        # CONCAT detection is orthogonal: these packets PASS structural
        # validation (they only look wrong when interior bytes are scanned).
        a55u1 = ('000402a43f00612501c0000025c062238202782183023f00a5098'
                 '0017183040000eec18a01058b032f0601c6069001008301019000'
                 '01a4000402a42f00612101c0000021621f')
        self.assertFalse(self.pd.is_desynced(bytes.fromhex(a55u1)))


class TestStallCheck(unittest.TestCase):
    """_stall_check distinguishes true EOF (None pins) from a live line that
    is merely idle (a level wait returns immediately at the same sample)."""

    def setUp(self):
        _, pd = _load_iso7816()
        self.inst = object.__new__(pd.Decoder)
        self.inst.samplenum = 100
        self.inst._prev_wait_sn = None
        self.inst._stall = 0

    def test_none_pins_is_eof(self):
        self.assertTrue(self.inst._stall_check(None))

    def test_advancing_sample_is_not_stall(self):
        for sn in range(100, 110):
            self.inst.samplenum = sn
            self.assertFalse(self.inst._stall_check([1]))

    def test_repeated_same_sample_is_bounded_stall(self):
        results = []
        for _ in range(10):
            self.inst.samplenum = 100
            results.append(self.inst._stall_check([1]))
        self.assertFalse(results[0])
        self.assertIn(True, results)

    def test_untracked_level_wait_never_stalls(self):
        # An idle-level wait repeats at the same sample on a live idle line;
        # with track=False it must not be flagged as EOF.
        for _ in range(10):
            self.inst.samplenum = 100
            self.assertFalse(self.inst._stall_check([1], track=False))
        self.assertEqual(self.inst._stall, 0)
        self.assertIsNone(self.inst._prev_wait_sn)

    def test_untracked_resets_stall_window(self):
        for _ in range(6):
            self.inst.samplenum = 100
            self.inst._stall_check([1])  # would trip the tracked stall
        self.assertTrue(self.inst._stall > 4)
        self.inst._stall_check([1], track=False)
        self.assertFalse(self.inst._stall_check([1]))  # window reset


class TestAtEof(unittest.TestCase):
    """decode_step must not treat a replay-only step (no sample progress) as
    end-of-capture, but must still terminate a genuinely stuck stream."""

    def setUp(self):
        _, pd = _load_iso7816()
        self.inst = object.__new__(pd.Decoder)
        self.inst.samplenum = 500
        self.inst._last_sn = 500
        self.inst._no_advance = 0
        self.inst._eof = False
        self.inst._replay = collections.deque()
        self.inst.peeked_byte = None

    def test_advancing_is_not_eof(self):
        self.inst.samplenum = 501
        self.assertFalse(self.inst._at_eof())

    def test_stuck_with_nothing_queued_is_eof(self):
        self.assertTrue(self.inst._at_eof())

    def test_pending_replay_is_not_eof(self):
        self.inst._replay.append(0x00)
        self.assertFalse(self.inst._at_eof())

    def test_pending_replay_is_bounded(self):
        self.inst._replay.append(0x00)
        for _ in range(64):
            self.assertFalse(self.inst._at_eof())
        self.assertTrue(self.inst._at_eof())

    def test_explicit_eof_wins(self):
        self.inst._eof = True
        self.inst.samplenum = 600
        self.assertTrue(self.inst._at_eof())


class TestEndOfStream(unittest.TestCase):
    """decode() must let end-of-stream exceptions propagate.

    Newer libsigrokdecode signals end-of-capture from wait() with
    EOFError('samples exhausted') (older versions use SystemError).
    libsigrokdecode accepts either as normal decode() termination, so
    swallowing them turns a clean end into a flood of DECODE ERROR retries.
    """

    def setUp(self):
        _, pd = _load_iso7816()
        self.pd = pd

    def _decode_raising(self, exc_cls):
        inst = object.__new__(self.pd.Decoder)
        inst.write_pcap_header = lambda: None
        inst.finish = lambda: None

        def step():
            raise exc_cls('samples exhausted')
        inst.decode_step = step
        return inst

    def test_eoferror_propagates(self):
        with self.assertRaises(EOFError):
            self._decode_raising(EOFError).decode()

    def test_systemerror_propagates(self):
        with self.assertRaises(SystemError):
            self._decode_raising(SystemError).decode()


class TestLineEventPayload(unittest.TestCase):
    """RST/VCC line-event payloads (GSMTAP sub_type 0x10/0x11), including the
    CLK-frequency extension (v1.9.0)."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def test_base_payload_without_rate(self):
        self.assertEqual(self.pd.line_event_payload(0, 1), b'\x00\x01\x00')
        self.assertEqual(self.pd.line_event_payload(1, 0, None), b'\x01\x00\x00')

    def test_payload_with_clk_rate(self):
        p = self.pd.line_event_payload(0, 1, 4800000)
        self.assertEqual(len(p), 7)
        self.assertEqual(p[0], 0)              # deasserted
        self.assertEqual(p[1], 1)              # resulting level: high
        self.assertEqual(p[2], self.pd.LINE_EVENT_FLAG_CLK_HZ)
        self.assertEqual(int.from_bytes(p[3:7], 'big'), 4800000)

    def test_rate_absent_when_unknown(self):
        self.assertEqual(len(self.pd.line_event_payload(1, 0, None)), 3)
        self.assertEqual(len(self.pd.line_event_payload(1, 0, 0)), 3)

    def test_legacy_prefix_preserved(self):
        # Consumers that read only bytes 0-1 (SIMtrace Analyser's
        # decode_line_event) must see the same direction/level as before.
        p = self.pd.line_event_payload(1, 0, 3579000)
        self.assertEqual(p[:2], b'\x01\x00')

    def test_flag_constant(self):
        self.assertEqual(self.pd.LINE_EVENT_FLAG_CLK_HZ, 0x01)


class TestDecodeStep(unittest.TestCase):
    """Byte-replay harness for the DATA-state gate chain in decode_step().

    The rest of the suite exercises only pure functions and leaf methods;
    these tests drive the real state machine with a scripted byte queue so
    the CLA/INS acceptance rules are pinned on the framing path (gate
    ordering, header read, one-byte re-frame, exchange assembly), not just
    in the predicates.
    """

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def _make(self, byte_seq):
        inst = object.__new__(self.pd.Decoder)
        inst.reset()
        inst.samplenum = 0
        inst._inverse_convention = False  # normally set by start()
        inst._atr_parsed = True           # keep 0x3B on the DATA path
        inst._primed = True               # skip the first-sample RST/VCC priming
        inst._at_eof = lambda: False
        inst.state = 'DATA'
        inst.hasT0 = True
        inst.hasT1 = False
        inst.bit_samples = 100            # ETU known: skip _measure_etu()
        inst._pps_speed_changed = False
        inst._resync = False
        inst.out_ann = 0
        inst.emitted = []
        inst.discarded = []
        inst._bytes = collections.deque(byte_seq)

        def pop_byte():
            if inst._replay:
                return inst._replay.popleft()
            return inst._bytes.popleft() if inst._bytes else None

        def peek_byte():
            b = inst._replay[0] if inst._replay else (
                inst._bytes[0] if inst._bytes else None)
            inst.peeked_samplenum = inst.samplenum
            return b

        inst.read_byte = pop_byte
        inst.read_first_byte = pop_byte
        inst._consume_first = pop_byte
        inst.peek_byte = peek_byte
        # The re-align / PPS / ATR / annotation paths are not under test.
        inst.resync_idle = lambda: None
        inst.handle_pps = lambda: None
        inst.handle_atr = lambda pins: None
        inst.put = lambda *a, **k: None
        inst.log = lambda *a, **k: None
        inst._note_discard = lambda value, reason, idle=False: \
            inst.discarded.append((value, reason, idle))
        inst._note_pre_sw = lambda value, reason: \
            inst.discarded.append((value, reason, True))
        inst.emit_packet = lambda sub_type, payload, ss, es, flags=0: \
            inst.emitted.append((bytes(payload), flags))
        # The vectors never depend on sample positions; a benign wait()
        # keeps an unrelated wait call from crashing the harness.
        inst.wait = lambda cond=None: [1] * 8
        return inst

    def test_9e_9f_are_status_words(self):
        # ISO 7816-3 10.3.3 Table 11: '9X' is SW1.  The old code treated
        # 9E/9F as an "extended-length" procedure byte and consumed SW2 as
        # a bogus length, losing the status word.
        for sw1 in (0x9e, 0x9f):
            with self.subTest(sw1=sw1):
                inst = self._make(bytes.fromhex('00a40000023f00')
                                  + bytes([sw1, 0x00]))
                self.assertTrue(inst.decode_step())
                self.assertEqual(
                    inst.emitted,
                    [(bytes.fromhex('00a40000023f00') + bytes([sw1, 0x00]), 0)])

    def test_parity_error_flags_bad_fcs(self):
        # A parity error is annotated and must also reach downstream as
        # GSMTAP_FLAG_BAD_FCS on the emitted packet.
        inst = self._make(bytes.fromhex('00a40000023f009000'))
        orig = inst.read_byte

        def read():
            b = orig()
            if b == 0x3f:
                inst._parity_errors += 1
            return b

        inst.read_byte = read
        self.assertTrue(inst.decode_step())
        self.assertEqual(len(inst.emitted), 1)
        self.assertTrue(inst.emitted[0][1] & self.pd.GSMTAP_FLAG_BAD_FCS)

    def test_extended_channel_exchange_frames(self):
        # 'CX' STATUS on channel 4 (v1.9.3): the whole exchange must be
        # read and emitted clean.
        inst = self._make(bytes.fromhex('c0f20000009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('c0f20000009000'), 0)])
        self.assertEqual(inst.discarded, [])

    def test_ex_class_exchange_frames(self):
        # 'EX' STATUS on channel 6 with SM (b6 = 1): same.
        inst = self._make(bytes.fromhex('e2f20000009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('e2f20000009000'), 0)])
        self.assertEqual(inst.discarded, [])

    def test_bit_dense_valid_cla_is_not_idle_noise(self):
        # 0x5F was accepted by plausible_cla() all along but always
        # discarded by the idle-noise gate before v1.9.3 (dead code): the
        # framing path must consume it as a command byte.
        inst = self._make(bytes.fromhex('5fa40004009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('5fa40004009000'), 0)])
        self.assertEqual(inst.discarded, [])

    def test_text_byte_boundary_is_discarded_not_framed(self):
        # xiaomi_mi_a1_coldboot regression byte: the menu-text 'a' (0x61)
        # at a mis-framed boundary is a suspicious CLA (not a frame start
        # and not idle noise) -- exactly one byte is consumed.
        inst = self._make(bytes.fromhex('612000c000621e'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted, [])
        self.assertEqual(len(inst.discarded), 1)
        self.assertEqual(inst.discarded[0][0], 0x61)
        self.assertIn('suspicious CLA', inst.discarded[0][1])
        self.assertEqual(bytes(inst._bytes), bytes.fromhex('2000c000621e'))

    def test_invalid_ins_re_frame_recovers_command(self):
        # A stray leading byte (0x1C) shifts the header; the invalid-INS
        # window (INS 0x00) drops only that byte and re-frames the real
        # command, which is emitted intact on the next step.
        inst = self._make(bytes.fromhex('1c00a40004009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted, [])
        self.assertEqual(inst.discarded[0][0], 0x1c)
        self.assertIn('invalid INS', inst.discarded[0][1])
        self.assertEqual(list(inst._replay), [0x00, 0xA4, 0x00, 0x04])
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('00a40004009000'), 0)])

    def test_data_0x3b_is_not_an_atr_after_traffic(self):
        # Once an APDU has been emitted, a DATA-state 0x3B is data misread
        # at a frame boundary, not an ATR: it falls through to the
        # suspicious-CLA discard instead of calling handle_atr.
        inst = self._make(bytes.fromhex('3b80900000'))
        inst._atr_parsed = False
        inst._apdu_seen = True
        called = []
        inst.handle_atr = lambda pins: called.append(pins)
        inst.decode_step()
        self.assertEqual(called, [])
        self.assertEqual(len(inst.discarded), 1)
        self.assertEqual(inst.discarded[0][0], 0x3B)

    def test_data_0x3b_before_traffic_is_atr_candidate(self):
        # Before any APDU the byte is still a legitimate ATR candidate
        # (a capture starting between RST deassert and the ATR).
        inst = self._make(bytes.fromhex('3b80900000'))
        inst._atr_parsed = False
        inst._apdu_seen = False
        called = []
        inst.handle_atr = lambda pins: called.append(pins)
        inst.decode_step()
        self.assertEqual(len(called), 1)

    def test_data_0x3f_before_traffic_is_atr_candidate(self):
        # Inverse-convention ATRs (TS=0x3F) are candidates too.
        inst = self._make(bytes.fromhex('3f100000'))
        inst._atr_parsed = False
        inst._apdu_seen = False
        called = []
        inst.handle_atr = lambda pins: called.append(pins)
        inst.decode_step()
        self.assertEqual(len(called), 1)

    def test_inverse_ts_raw_pattern_is_an_atr_candidate(self):
        # A real inverse TS decodes as 0x03 through the direct reader; the
        # raw moments 5-7 (LLL) mark it as the 0x3F candidate.
        inst = self._make(bytes.fromhex('03100000'))
        inst._atr_parsed = False
        inst._apdu_seen = False
        inst.bits = [0, 1, 1, 0, 0, 0, 0, 0, 0, 1]
        called = []
        inst.handle_atr = lambda pins: called.append(pins)
        inst.decode_step()
        self.assertEqual(len(called), 1)

    def test_idle_noise_still_discarded(self):
        # 0xFE (all-1s minus one bit) is not a valid class: unchanged
        # idle-noise discard.
        inst = self._make(bytes.fromhex('fea40004009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted, [])
        self.assertEqual(len(inst.discarded), 1)
        self.assertEqual(inst.discarded[0][0], 0xfe)
        self.assertIn('idle-line noise', inst.discarded[0][1])

    def test_immediate_sw_rejection_frames(self):
        # A command rejected with SW1 SW2 instead of an ACK (ISO 7816-3
        # §10.3.3) must not be read as command data; the exchange and the
        # following one must frame separately.
        inst = self._make(bytes.fromhex('00b00000106a82' +
                                        '00a40004009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('00b00000106a82'), 0)])
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted[1],
                         (bytes.fromhex('00a40004009000'), 0))

    def test_short_response_is_split_and_flagged(self):
        # Lr < Le (6282 end-of-file): the SW inside the P3-byte read ends
        # the response, and the packet is flagged BAD_FCS (it used to be a
        # silent total loss).
        inst = self._make(bytes.fromhex('00b0000010b012349000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('00b000001012349000'),
                           self.gs.GSMTAP_FLAG_BAD_FCS)])

    def test_short_response_replays_following_exchange(self):
        # A short response followed by another command: the split must
        # replay the tail so the next exchange is framed intact.
        inst = self._make(bytes.fromhex('00b0000010b012349000' +
                                        '00a40004009000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted[0],
                         (bytes.fromhex('00b000001012349000'),
                          self.gs.GSMTAP_FLAG_BAD_FCS))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted[1],
                         (bytes.fromhex('00a40004009000'), 0))

    def test_le_256_response_data_is_kept(self):
        # P3=0 in an outgoing command is Le=256 (ISO 7816-3 §10.3.2): the
        # data after the ACK must be appended, not discarded — including a
        # data byte that happens to equal INS.
        payload = 'a5' * 8 + 'b0' + 'a5' * 7
        inst = self._make(bytes.fromhex('00b0000000b0' + payload + '9000'))
        self.assertTrue(inst.decode_step())
        self.assertEqual(inst.emitted,
                         [(bytes.fromhex('00b0000000' + payload + '9000'), 0)])


class TestAtrHuntDetect(unittest.TestCase):
    """The ATR-hunt command-detect handoff in handle_atr(), driven by a
    scripted byte queue (the hunt logic itself is not otherwise covered)."""

    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def _make(self, byte_seq):
        inst = object.__new__(self.pd.Decoder)
        inst.reset()
        inst.samplenum = 0
        inst.ss = 0
        inst._inverse_convention = False  # normally set by start()
        inst._samples_per_clock = 4.0     # skip _measure_clock_period()
        inst.bit_samples = 100            # skip _compute_bit_samples()
        inst.out_ann = 0
        inst.out_python = 0
        inst.options = {'protocol': 'T=0'}
        inst._atr_parsed = False
        inst.emitted = []
        inst.emit_packet = lambda st, pl, ss, es, flags=0: \
            inst.emitted.append((st, bytes(pl), flags))
        inst.hasT0 = False                # start() defaults; a handoff flips it
        inst.hasT1 = False
        inst._bytes = collections.deque(byte_seq)

        def pop_byte():
            if inst._replay:
                return inst._replay.popleft()
            return inst._bytes.popleft() if inst._bytes else None

        def peek_byte():
            b = inst._replay[0] if inst._replay else (
                inst._bytes[0] if inst._bytes else None)
            inst.peeked_samplenum = inst.samplenum
            return b

        inst.read_byte = pop_byte
        inst.read_first_byte = pop_byte
        inst._consume_first = pop_byte
        inst.peek_byte = peek_byte
        inst.put = lambda *a, **k: None
        inst.log = lambda *a, **k: None
        inst.wait = lambda cond=None: [1] * 8
        return inst

    def test_handoff_on_extended_channel_cla(self):
        # 0xC4 (channel 8, no SM) + 0xA4 (SELECT): a command header, not a
        # non-TS byte; it is replayed to the DATA state.
        inst = self._make([0xC4, 0xA4])
        inst.handle_atr(None)
        self.assertEqual(inst.state, 'DATA')
        self.assertEqual(list(inst._replay), [0xC4])
        self.assertTrue(inst.hasT0)

    def test_handoff_on_odd_ins_89(self):
        # The TS 102 221 AUTHENTICATE '89' form (v1.9.3): the second byte
        # only qualifies because ODD_INS accepts it.
        inst = self._make([0xC4, 0x89])
        inst.handle_atr(None)
        self.assertEqual(inst.state, 'DATA')
        self.assertEqual(list(inst._replay), [0xC4])

    def test_no_handoff_on_basic_channel_cla(self):
        # CLA 0x00 is excluded by design (pre-activation noise).
        inst = self._make([0x00, 0xA4])
        inst.handle_atr(None)
        self.assertEqual(inst.state, 'ATR')
        self.assertEqual(list(inst._replay), [])

    def test_no_handoff_on_invalid_ins(self):
        # 0x61 is not a valid INS: the pair stays on the hunt path.
        inst = self._make([0xC4, 0x61])
        inst.handle_atr(None)
        self.assertEqual(inst.state, 'ATR')
        self.assertEqual(list(inst._replay), [])

    def test_eof_after_plausible_cla_is_clean(self):
        # Capture ends right after a plausible CLA byte: the hunt must
        # return cleanly.  It used to call plausible_ins(None) -> TypeError
        # (seen only by decode()'s crash protection).
        inst = self._make([0xC4])
        inst.handle_atr(None)             # must not raise
        self.assertEqual(inst.state, 'ATR')
        self.assertEqual(list(inst._replay), [])

    def test_bare_ts_t0_is_not_committed_as_an_atr(self):
        # A data byte 0x3B followed by 0x00 looks like a bare TS+T0 ATR.
        # It must not be emitted or force clock_skip=372 (a mid-session
        # data 0x3B used to fabricate an ATR).
        inst = self._make([0x3B, 0x00])
        inst.handle_atr(None)
        self.assertFalse(inst._atr_parsed)
        self.assertEqual(inst.emitted, [])
        self.assertEqual(inst.state, 'DATA')

    def test_truncated_atr_ta_is_clean(self):
        # T0 says TA1 present but the capture ends: the parse must return
        # without committing an ATR (or raising on the None byte).
        inst = self._make([0x3B, 0x10])
        inst.handle_atr(None)
        self.assertFalse(inst._atr_parsed)
        self.assertEqual(inst.emitted, [])

    def test_inverse_ts_pattern_is_parsed(self):
        # 0x03 + the raw inverse TS pattern must be committed as 0x3F and
        # switch the readers to the inverse convention.
        inst = self._make([0x03, 0x10, 0x95])
        inst.bits = [0, 1, 1, 0, 0, 0, 0, 0, 0, 1]
        inst.handle_atr(None)
        self.assertTrue(inst._atr_parsed)
        self.assertTrue(inst._inverse_convention)
        self.assertEqual(inst.ATR, [0x3f, 0x10, 0x95])
        self.assertEqual(len(inst.emitted), 1)

    def test_atr_with_parity_error_is_ignored(self):
        # A real ATR is parity-clean.  A data run that parses as an ATR but
        # has a parity error must not commit the rate (e.g. test_8's
        # fabricated 3b80900000).
        inst = self._make([0x3B, 0x10, 0x95])
        orig = inst.read_byte

        def read():
            b = orig()
            if b == 0x10:
                inst._parity_errors += 1
            return b

        inst.read_byte = read
        inst.handle_atr(None)
        self.assertFalse(inst._atr_parsed)
        self.assertEqual(inst.emitted, [])
        self.assertEqual(inst.state, 'DATA')


if __name__ == '__main__':
    unittest.main()
