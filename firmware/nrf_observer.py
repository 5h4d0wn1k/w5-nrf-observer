#!/usr/bin/env python3
"""W5 — nRF24 Cross-Protocol Observer.

Byte-level nRF24L01+ Enhanced ShockBurst (ESB) analysis:

  * ESB PDU parse pipeline: address -> control (len/PID/NO_ACK) -> payload -> CRC
  * CRC-8 (poly 0x07) and CRC-16 (CCITT-FALSE 0x1021) validation off the wire
  * mousejack-style HID decode + vendor OUI mapping
  * channel-occupancy histogram + deterministic synthetic fixture / pcap ingestion

All work is on bytes (offscreen); passive observation only, no radio emission.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

NRF_CHANNELS = list(range(2, 84, 2))

# nRF24 OUI/vendor map (curated; prefix -> vendor)
OUI_VENDORS = {
    "aa:bb:cc": "Nordic-sample",
    "11:22:33": "Logitech",
    "c0:28:8d": "Logitech",
    "3c:4a:92": "Logitech (Unifying)",
}


def vendor_for_address(address_bytes):
    """Map the first 3 bytes of a 5-byte ESB address to a vendor."""
    prefix = ":".join(f"{b:02x}" for b in address_bytes[:3])
    return OUI_VENDORS.get(prefix, "unknown")


MOUSEJACK_PATTERNS = [
    {"preamble": bytes.fromhex("aa bb cc dd ee"), "protocol": "CrazyRadio PA",
     "desc": "Enhanced ShockBurst (ESB) keyboard/mouse report"},
    {"preamble": bytes.fromhex("11 22 33 44 55"), "protocol": "Logitech Unifying",
     "desc": "Logitech-compatible HID over nRF24"},
]

HID_KEYCODES = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0a: "g",
    0x0b: "h", 0x0c: "i", 0x0d: "j", 0x0e: "k", 0x0f: "l", 0x10: "m", 0x11: "n",
    0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t", 0x18: "u",
    0x19: "v", 0x1a: "w", 0x1b: "x", 0x1c: "y", 0x1d: "z",
    0x1e: "1", 0x1f: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7",
    0x25: "8", 0x26: "9", 0x27: "0", 0x28: "ENTER", 0x29: "ESC", 0x2a: "BACKSPACE",
    0x2b: "TAB", 0x2c: "SPACE",
}


def crc8(data: bytes, poly: int = 0x07, init: int = 0xFF) -> int:
    """nRF24 CRC-8 (poly 0x07, init 0xFF)."""
    crc = init
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def crc16(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    """nRF24 CRC-16 (CCITT-FALSE poly 0x1021, init 0xFFFF)."""
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ poly) & 0xFFFF) if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_esb_pdu(address: bytes, payload: bytes, crc_bits: int = 8,
                  pid: int = 0, no_ack: int = 0) -> bytes:
    """Build a byte-exact ESB PDU: address + control + payload + CRC."""
    if len(address) != 5:
        raise ValueError("ESB address must be 5 bytes")
    control = (no_ack << 7) | (pid & 0x03) << 6 | (len(payload) & 0x3F)
    body = address + bytes([control]) + payload
    if crc_bits == 16:
        crc = crc16(body).to_bytes(2, "big")
    elif crc_bits == 24:
        raise ValueError("24-bit CRC not implemented")
    else:
        crc = bytes([crc8(body)])
    return body + crc


def parse_esb_pdu(pdu_bytes: bytes):
    """Parse an ESB PDU: address, control (len/PID/NO_ACK), payload, CRC validation."""
    if len(pdu_bytes) < 10:
        return None
    address = pdu_bytes[:5]
    control = pdu_bytes[5]
    length = control & 0x3F
    pid = (control >> 6) & 0x03
    no_ack = (control >> 7) & 0x01
    payload = pdu_bytes[6:6 + length] if len(pdu_bytes) >= 6 + length else pdu_bytes[6:]
    # try 8-bit then 16-bit CRC over what precedes the trailing CRC
    crc_ok = False
    crc_bits = 0
    if len(pdu_bytes) - 6 >= length + 1:
        crc_ok = crc8(pdu_bytes[:6 + length]) == pdu_bytes[6 + length]
        crc_bits = 8 if crc_ok else 0
    if not crc_ok and len(pdu_bytes) - 6 >= length + 2:
        calc = crc16(pdu_bytes[:6 + length])
        got = (pdu_bytes[6 + length] << 8) | pdu_bytes[6 + length + 1]
        crc_ok = calc == got
        crc_bits = 16 if crc_ok else 0
    return {
        "address": address,
        "address_hex": address.hex(),
        "length": length,
        "pid": pid,
        "no_ack": no_ack,
        "payload": payload,
        "payload_hex": payload.hex(),
        "crc_ok": crc_ok,
        "crc_bits": crc_bits,
    }


def identify_protocol(pdu_bytes):
    for pattern in MOUSEJACK_PATTERNS:
        if pdu_bytes[:len(pattern["preamble"])] == pattern["preamble"]:
            return pattern
    return {"protocol": "Unknown", "desc": "Unrecognized nRF24 preamble"}


def decode_mousejack_payload(payload):
    """HID report decode: report_id / modifier / keycodes -> human label."""
    if len(payload) < 4:
        return None
    report_id = payload[0]
    modifier = payload[1]
    keycodes = list(payload[2:])
    mods = {0x01: "L-Ctrl", 0x02: "L-Shift", 0x04: "L-Alt", 0x08: "L-GUI",
            0x10: "R-Ctrl", 0x20: "R-Shift", 0x40: "R-Alt", 0x80: "R-GUI"}
    mod_str = [n for bit, n in mods.items() if modifier & bit]
    chars = [HID_KEYCODES.get(k, f"0x{k:02x}") for k in keycodes if k]
    return {
        "report_id": report_id,
        "modifier": modifier,
        "modifiers": mod_str,
        "keycodes": keycodes,
        "chars": chars,
        "text": "".join(c for c in chars if len(c) == 1),
        "raw": payload.hex(),
    }


def build_channel_histogram(packets):
    hist = Counter()
    for pkt in packets:
        ch = pkt.get("channel")
        if ch is not None:
            hist[ch] += 1
    return hist


def render_histogram(hist, bar_width=30):
    if not hist:
        return ""
    max_count = max(hist.values()) or 1
    lines = [f"{'CH':>4} | {'Count':>5} | Histogram", "-" * (8 + bar_width + 5)]
    for ch in sorted(hist):
        bar = "#" * int((hist[ch] / max_count) * bar_width)
        lines.append(f"{ch:>4} | {hist[ch]:>5} | {bar}")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Deterministic synthetic fixture (pure in-repo, no radio)
# ----------------------------------------------------------------------

ADDR_A = bytes.fromhex("aa bb cc dd ee")
ADDR_L = bytes.fromhex("11 22 33 44 55")


def build_fixture_packets():
    """20 ESB PDUs spaced across nRF channels; mousejack-style HID payloads."""
    packets = []
    ts = 1700000000.000
    for i in range(20):
        ch = NRF_CHANNELS[i % len(NRF_CHANNELS)]
        addr = ADDR_A if i % 2 == 0 else ADDR_L
        payload = bytes([0x01, 0x00, 0x04 + (i % 6)]) + bytes(range(0x30 + i % 9, 0x40))
        pdu = build_esb_pdu(addr, payload, crc_bits=8, pid=i % 4, no_ack=0)
        rssi = -40 - (i % 11)
        packets.append({"ts": round(ts + i * 10.1, 3), "channel": ch, "rssi": rssi, "pdu": pdu})
    return packets


def write_fixture_pcap(path: str) -> int:
    packets = build_fixture_packets()
    fc.write_pcap(path, [p["pdu"] for p in packets], ts=packets[0]["ts"])
    return len(packets)


def read_pcap_pdus(path: str) -> list[bytes]:
    return [r["data"] for r in fc.read_pcap(path)]


# ----------------------------------------------------------------------
# Observer pipeline
# ----------------------------------------------------------------------


class NRF24Observer:
    def __init__(self, packets=None, pcap_path=None):
        if pcap_path:
            pdus = read_pcap_pdus(pcap_path)
            self.packets = [{"ts": 0.0, "channel": None, "rssi": None, "pdu": p} for p in pdus]
        else:
            self.packets = packets if packets is not None else build_fixture_packets()
        self.decoded = []
        self.histogram = Counter()

    def parse_all(self):
        for pkt in self.packets:
            pdu = pkt["pdu"]
            parsed = parse_esb_pdu(pdu)
            proto = identify_protocol(pdu)
            vendor = vendor_for_address(parsed["address"]) if parsed else "unknown"
            decoded = decode_mousejack_payload(parsed["payload"]) if parsed and parsed["payload"] else None
            self.decoded.append({
                "channel": pkt.get("channel"),
                "rssi": pkt.get("rssi"),
                "timestamp": pkt.get("ts", 0.0),
                "pdu_len": len(pdu),
                "crc_ok": parsed["crc_ok"] if parsed else False,
                "crc_bits": parsed["crc_bits"] if parsed else 0,
                "address_hex": parsed["address_hex"] if parsed else "",
                "vendor": vendor,
                "protocol": proto["protocol"],
                "pid": parsed["pid"] if parsed else None,
                "payload_len": parsed["length"] if parsed else 0,
                "payload_hex": parsed["payload_hex"] if parsed else "",
                "hid": decoded,
            })
        return self.decoded

    def build_histogram(self):
        self.histogram = build_channel_histogram(self.decoded)
        return self.histogram

    def run_analysis(self):
        self.parse_all()
        self.build_histogram()
        return self.decoded


def print_analysis(decoded, histogram):
    print("=" * 68)
    print("W5 — nRF24 Cross-Protocol Observer (byte-level, offline)")
    print("=" * 68)
    crc_ok = sum(1 for d in decoded if d["crc_ok"])
    print(f"\n[+] PDUs: {len(decoded)}   CRC-valid: {crc_ok}   "
          f"channels: {len(histogram)}   radio_emitted=False")
    if any(h for d in decoded if (h := d["hid"])):
        print("\n--- HID decodes ---")
        for d in decoded:
            if d["hid"]:
                hid = d["hid"]
                mods = "+".join(hid["modifiers"]) or "none"
                text = hid["text"] or "/".join(hid["chars"])
                print(f"  CH{d['channel'] or '?':>2} | {d['vendor']:<20} | {d['protocol']:<18} "
                      f"| mod=[{mods}] | '{text}' | {hid['raw']}")
    print("\n" + render_histogram(histogram))
    print(f"\n[+] Analysis complete — no radio emitted.")
    print("=" * 68)


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w5-nrf-observer",
        description="nRF24L01+ ESB cross-protocol observer: byte-exact PDU parse, "
                    "CRC-8/16 validation, HID decode, OUI vendor map, channel histogram "
                    "(pure-stdlib; offline; no radio).")
    p.add_argument("--pcap", metavar="PATH", help="ingest ESB PDUs from a pcap fixture")
    p.add_argument("--gen-fixture", metavar="PATH", help="write deterministic ESB fixture pcap")
    p.add_argument("--json", metavar="PATH", help="write JSON report")
    return p


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    observer = NRF24Observer(pcap_path=args.pcap)
    decoded = observer.run_analysis()
    print_analysis(decoded, observer.histogram)
    if args.gen_fixture:
        d = os.path.dirname(args.gen_fixture)
        if d:
            os.makedirs(d, exist_ok=True)
        n = write_fixture_pcap(args.gen_fixture)
        print(f"\n[+] fixture -> {args.gen_fixture} ({n} PDUs)")
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        payload = {
            "name": "w5-nrf-observer",
            "radio_emitted": False,
            "pdus": decoded,
            "histogram": dict(observer.histogram),
            "note": "passive observation; ESB PDUs parsed byte-level on bytes",
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    return main([])


if __name__ == "__main__":
    raise SystemExit(main())