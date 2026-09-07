#!/usr/bin/env python3
"""Byte-exact unit tests for w5-nrf-observer."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import nrf_observer as no
from firmware import frame_core as fc


class CrcTest(unittest.TestCase):
    def test_crc8_reference(self):
        # CRC-8 poly 0x07 init 0xFF over "123456789" == 0xFB (nRF24 init)
        self.assertEqual(no.crc8(b"123456789"), 0xFB)

    def test_crc16_reference(self):
        # CRC-16/CCITT-FALSE over "123456789" == 0x29B1
        self.assertEqual(no.crc16(b"123456789"), 0x29B1)


class PduBuildParseTest(unittest.TestCase):
    def test_build_then_parse_roundtrip(self):
        pdu = no.build_esb_pdu(bytes.fromhex("aa bb cc dd ee"),
                               bytes(range(0x30, 0x40)), crc_bits=8, pid=2)
        parsed = no.parse_esb_pdu(pdu)
        self.assertEqual(parsed["length"], 16)
        self.assertEqual(parsed["pid"], 2)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["crc_bits"], 8)

    def test_crc16_is_validated(self):
        pdu = no.build_esb_pdu(bytes.fromhex("11 22 33 44 55"), b"abcd",
                               crc_bits=16, no_ack=1)
        parsed = no.parse_esb_pdu(pdu)
        self.assertEqual(parsed["crc_bits"], 16)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["no_ack"], 1)

    def test_bad_crc_detected(self):
        pdu = bytearray(no.build_esb_pdu(bytes.fromhex("aa bb cc dd ee"), b"payload"))
        pdu[-1] ^= 0xFF
        self.assertFalse(no.parse_esb_pdu(bytes(pdu))["crc_ok"])


class VendorMapTest(unittest.TestCase):
    def test_oui_mapping(self):
        self.assertEqual(no.vendor_for_address(bytes.fromhex("aa bb cc dd ee")),
                         "Nordic-sample")
        self.assertEqual(no.vendor_for_address(bytes.fromhex("11 22 33 44 55")),
                         "Logitech")
        self.assertEqual(no.vendor_for_address(bytes.fromhex("de ad be ef 01")),
                         "unknown")


class HidDecodeTest(unittest.TestCase):
    def test_keycode_text(self):
        # modifier none + keycodes a/b/c
        hid = no.decode_mousejack_payload(bytes([0x01, 0x00, 0x04, 0x05, 0x06]))
        self.assertEqual(hid["text"], "abc")
        self.assertEqual(hid["modifiers"], [])

    def test_modifier_decode(self):
        hid = no.decode_mousejack_payload(bytes([0x01, 0x02, 0x04, 0x05]))
        self.assertIn("L-Shift", hid["modifiers"])


class ObserverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.obs = no.NRF24Observer()
        cls.decoded = cls.obs.run_analysis()

    def test_parses_all_pdus(self):
        self.assertEqual(len(self.decoded), 20)
        self.assertTrue(all(d["crc_ok"] for d in self.decoded))

    def test_histogram_channels(self):
        self.assertTrue(len(self.obs.histogram) > 1)

    def test_hid_decodes_present(self):
        self.assertTrue(any(d["hid"] for d in self.decoded))


class FixtureTest(unittest.TestCase):
    def test_write_read_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "esb.pcap")
            n = no.write_fixture_pcap(path)
            self.assertEqual(n, 20)
            pdus = no.read_pcap_pdus(path)
            self.assertEqual(len(pdus), 20)


class CLITest(unittest.TestCase):
    def test_demo_exit_zero(self):
        self.assertEqual(no.run_demo(), 0)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = no.main(["--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            data = json.load(open(out))
            self.assertEqual(data["name"], "w5-nrf-observer")
            self.assertFalse(data["radio_emitted"])

    def test_pcap_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "esb.pcap")
            no.write_fixture_pcap(path)
            rc = no.main(["--pcap", path])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()