"""Unit tests for GSMTAP flag plumbing + decoder desync helpers.

pd.py imports the libsigrokdecode bindings, which are not always present
in a bare Python env, so we stub a minimal `sigrokdecode` module and load
the real pd.py / gsmtap_stream.py sources under the `iso7816` package
name (mirroring how libsigrokdecode loads a decoder directory).
"""

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


if __name__ == '__main__':
    unittest.main()
