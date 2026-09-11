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


class TestDesyncHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gs, cls.pd = _load_iso7816()

    def test_plausible_sw_accepts_valid_classes(self):
        for sw1 in list(range(0x60, 0x70)) + list(range(0x90, 0xA0)):
            self.assertTrue(self.pd.plausible_sw(sw1), hex(sw1))

    def test_plausible_sw_rejects_garbage(self):
        for sw1 in (0x00, 0x01, 0x3B, 0x3F, 0xA0, 0xFF, 0x88, 0x5F):
            self.assertFalse(self.pd.plausible_sw(sw1), hex(sw1))

    def test_max_tpdu_len(self):
        self.assertEqual(self.pd.MAX_TPDU_LEN, 271)

    def test_is_desynced_clean_packets(self):
        # 7-byte: header(5) + proc(1) + SW2(1) ending in a 9x SW1
        self.assertFalse(self.pd.is_desynced(b'\x00\xa4\x00\x04\x02\x60\x90'))
        # ACK-style GET RESPONSE (header + proc + payload + SW 9000)
        self.assertFalse(self.pd.is_desynced(
            b'\x00\xc0\x00\x00\x25\xc0\x62\x23\x90\x00'))

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
        # Interindustry CLA digits 0x/1x/4x/5x are structurally valid
        # (ISO 7816-4): includes logical channels 0x01-0x03, secure
        # messaging 0x0C, chaining 0x10, and the SM/structural 0x4x/0x5x.
        for cla in (0x01, 0x02, 0x03, 0x0C, 0x10, 0x14, 0x44, 0x50, 0x54):
            pkt = bytes([cla, 0xa4, 0x00, 0x04, 0x00, 0x90, 0x00])
            with self.subTest(cla=cla):
                self._valid(pkt)

    def test_valid_cla_channel1_select_after_manage_channel(self):
        # The command that follows MANAGE CHANNEL (00 70 00 00 01) opening
        # logical channel 1 legitimately uses CLA 0x01.  This exact type
        # (SELECT by AID) is what the A55/S21p traces carry.
        self._valid(b'\x01\xa4\x00\x04\x0c'
                    b'\xa0\x00\x00\x00\x63\x50\x4b\x43\x53\x2d\x31\x35'
                    b'\x6a\x82')

    def test_invalid_cla_proprietary_unseen(self):
        # 0xC0 is proprietary but not a class these cards emit; stays invalid
        self._invalid(b'\xc0\xa4\x00\x04\x00\x90\x00', 'invalid CLA')

    def test_invalid_too_short(self):
        self._invalid(b'\x00\xa4\x00\x04\x00\x90', 'too short')

    def test_invalid_cla(self):
        self._invalid(b'\xff\xa4\x00\x04\x00\x90\x00', 'invalid CLA')

    def test_invalid_ins_zero(self):
        self._invalid(b'\x00\x00\x00\x04\x00\x90\x00', 'invalid INS')

    def test_invalid_ins_lsb_odd(self):
        self._invalid(b'\x00\xa5\x00\x04\x00\x90\x00', 'invalid INS')

    def test_invalid_ins_sw_collision(self):
        self._invalid(b'\x00\x64\x00\x04\x00\x90\x00', 'invalid INS')

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


if __name__ == '__main__':
    unittest.main()
