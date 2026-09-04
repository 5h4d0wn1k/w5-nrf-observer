#!/usr/bin/env python3
"""W5 — nRF24 Cross-Protocol Observer. Parse ESB PDUs, decode packets, channel-occupancy histogram."""

import sys
import struct
import math
from collections import Counter, defaultdict


EMBEDDED_ESB_PACKETS = [
    {"channel": 2, "pdu": bytes.fromhex("aa bb cc dd ee 08 00 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c"), "rssi": -42, "ts": 0.001},
    {"channel": 4, "pdu": bytes.fromhex("aa bb cc dd ee 08 00 3c 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c"), "rssi": -55, "ts": 0.003},
    {"channel": 6, "pdu": bytes.fromhex("11 22 33 44 55 09 01 42 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d"), "rssi": -38, "ts": 0.005},
    {"channel": 8, "pdu": bytes.fromhex("aa bb cc dd ee 0a 02 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -61, "ts": 0.008},
    {"channel": 10, "pdu": bytes.fromhex("11 22 33 44 55 08 03 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c"), "rssi": -47, "ts": 0.010},
    {"channel": 12, "pdu": bytes.fromhex("aa bb cc dd ee 08 00 3c 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65"), "rssi": -52, "ts": 0.013},
    {"channel": 14, "pdu": bytes.fromhex("11 22 33 44 55 0a 01 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -68, "ts": 0.016},
    {"channel": 16, "pdu": bytes.fromhex("aa bb cc dd ee 08 02 3c 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c"), "rssi": -44, "ts": 0.018},
    {"channel": 18, "pdu": bytes.fromhex("11 22 33 44 55 09 03 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -59, "ts": 0.021},
    {"channel": 20, "pdu": bytes.fromhex("aa bb cc dd ee 08 00 3c 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c"), "rssi": -51, "ts": 0.024},
    {"channel": 22, "pdu": bytes.fromhex("11 22 33 44 55 0a 01 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -63, "ts": 0.027},
    {"channel": 24, "pdu": bytes.fromhex("aa bb cc dd ee 08 02 3c 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65"), "rssi": -46, "ts": 0.030},
    {"channel": 26, "pdu": bytes.fromhex("11 22 33 44 55 09 00 3c 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c"), "rssi": -55, "ts": 0.033},
    {"channel": 28, "pdu": bytes.fromhex("aa bb cc dd ee 0a 03 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -70, "ts": 0.036},
    {"channel": 30, "pdu": bytes.fromhex("11 22 33 44 55 08 01 3c 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c"), "rssi": -49, "ts": 0.039},
    {"channel": 32, "pdu": bytes.fromhex("aa bb cc dd ee 08 00 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c"), "rssi": -57, "ts": 0.042},
    {"channel": 2, "pdu": bytes.fromhex("11 22 33 44 55 09 02 3c 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65"), "rssi": -43, "ts": 0.045},
    {"channel": 4, "pdu": bytes.fromhex("aa bb cc dd ee 0a 03 3c 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c"), "rssi": -62, "ts": 0.048},
    {"channel": 6, "pdu": bytes.fromhex("aa bb cc dd ee 08 01 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c"), "rssi": -39, "ts": 0.051},
    {"channel": 8, "pdu": bytes.fromhex("11 22 33 44 55 09 00 3c 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e"), "rssi": -65, "ts": 0.054},
]

MOUSEJACK_PATTERNS = [
    {"preamble": bytes.fromhex("aa bb cc dd ee"), "protocol": "CrazyRadio PA", "desc": "Enhanced ShockBurst (ESB) keyboard/mouse report"},
    {"preamble": bytes.fromhex("11 22 33 44 55"), "protocol": "Logitech Unifying", "desc": "Logitech-compatible HID over nRF24"},
]

NRF_CHANNELS = list(range(2, 84, 2))


def parse_esb_pdu(pdu_bytes):
    """Parse an Enhanced ShockBurst PDU byte stream into address/payload."""
    if len(pdu_bytes) < 10:
        return None
    address = pdu_bytes[:5]
    control = pdu_bytes[5]
    length = control & 0x3F
    pid = (control >> 6) & 0x03
    no_ack = (control >> 7) & 0x01
    payload = pdu_bytes[6:6 + length] if len(pdu_bytes) >= 6 + length else pdu_bytes[6:]
    crc = pdu_bytes[-3:] if len(pdu_bytes) >= 3 + 6 else b""
    return {
        "address": address,
        "address_hex": address.hex(),
        "length": length,
        "pid": pid,
        "no_ack": no_ack,
        "payload": payload,
        "payload_hex": payload.hex(),
        "crc": crc,
    }


def identify_protocol(pdu_bytes):
    """Identify nRF24 protocol from preamble pattern."""
    for pattern in MOUSEJACK_PATTERNS:
        preamble = pattern["preamble"]
        if pdu_bytes[:len(preamble)] == preamble:
            return pattern
    return {"protocol": "Unknown", "desc": "Unrecognized nRF24 preamble"}


def decode_mousejack_payload(payload):
    """Decode a MouseJack-style HID payload into keystroke/button data."""
    if len(payload) < 4:
        return None
    report_id = payload[0]
    modifier = payload[1] if len(payload) > 1 else 0
    keycodes = list(payload[2:]) if len(payload) > 2 else []
    mod_str = []
    mods = {0x01: "L-Ctrl", 0x02: "L-Shift", 0x04: "L-Alt", 0x08: "L-GUI",
            0x10: "R-Ctrl", 0x20: "R-Shift", 0x40: "R-Alt", 0x80: "R-GUI"}
    for bit, name in mods.items():
        if modifier & bit:
            mod_str.append(name)
    return {
        "report_id": report_id,
        "modifier": modifier,
        "modifiers": mod_str,
        "keycodes": keycodes,
        "raw": payload.hex(),
    }


def build_channel_histogram(packets):
    """Build channel-occupancy histogram from captured packets."""
    hist = Counter()
    for pkt in packets:
        ch = pkt.get("channel", 0)
        hist[ch] += 1
    return hist


def render_histogram(hist, bar_width=30):
    """Render a text-based channel-occupancy histogram."""
    if not hist:
        return ""
    max_count = max(hist.values()) if hist else 1
    lines = []
    lines.append(f"{'CH':>4} | {'Count':>5} | Histogram")
    lines.append("-" * (8 + bar_width + 5))
    for ch in sorted(hist.keys()):
        count = hist[ch]
        bar_len = int((count / max_count) * bar_width) if max_count > 0 else 0
        bar = "#" * bar_len
        lines.append(f"{ch:>4} | {count:>5} | {bar}")
    return "\n".join(lines)


class NRF24Observer:
    """nRF24L01+ cross-protocol observation and analysis suite."""

    def __init__(self, packets=None):
        self.packets = packets or EMBEDDED_ESB_PACKETS
        self.decoded = []
        self.histogram = Counter()

    def parse_all(self):
        """Parse all embedded ESB packets."""
        print(f"[+] Parsing {len(self.packets)} ESB PDU captures...")
        for pkt in self.packets:
            pdu = pkt["pdu"]
            parsed = parse_esb_pdu(pdu)
            protocol = identify_protocol(pdu)
            decoded_hid = None
            if parsed and parsed["payload"]:
                decoded_hid = decode_mousejack_payload(parsed["payload"])
            entry = {
                "channel": pkt["channel"],
                "rssi": pkt["rssi"],
                "timestamp": pkt["ts"],
                "pdu_len": len(pdu),
                "parsed": parsed,
                "protocol": protocol,
                "decoded_hid": decoded_hid,
            }
            self.decoded.append(entry)
        print(f"[+] Decoded {len(self.decoded)} packets")
        return self.decoded

    def build_histogram(self):
        """Build channel-occupancy histogram."""
        self.histogram = build_channel_histogram(self.packets)
        print(f"[+] Channel histogram: {len(self.histogram)} unique channels")
        return self.histogram

    def print_decoded_packets(self):
        """Print decoded packets summary."""
        print("\n=== Decoded ESB Packets ===")
        print(f"{'#':>3} {'CH':>3} {'RSSI':>6} {'Protocol':<20} {'PID':>3} {'Len':>4} {'Payload Hex':<40}")
        print("-" * 85)
        for i, entry in enumerate(self.decoded):
            parsed = entry["parsed"]
            if parsed:
                pid = parsed["pid"]
                plen = parsed["length"]
                phex = parsed["payload_hex"][:40]
            else:
                pid = "-"
                plen = 0
                phex = ""
            proto = entry["protocol"]["protocol"]
            print(f"{i:>3} {entry['channel']:>3} {entry['rssi']:>5}dBm {proto:<20} {pid:>3} {plen:>4} {phex:<40}")

    def print_mousejack_decodes(self):
        """Print MouseJack-style decoded HID reports."""
        print("\n=== MouseJack HID Decodes ===")
        count = 0
        for entry in self.decoded:
            if entry["decoded_hid"]:
                hid = entry["decoded_hid"]
                mods = "+".join(hid["modifiers"]) if hid["modifiers"] else "none"
                print(f"  CH{entry['channel']:>2} | ReportID={hid['report_id']} | Modifiers=[{mods}] | Keys={hid['keycodes']} | Raw={hid['raw']}")
                count += 1
        if count == 0:
            print("  (no HID decodes)")
        return count

    def run_analysis(self):
        """Run the full nRF24 observation analysis."""
        print("=" * 60)
        print("  W5 — nRF24 Cross-Protocol Observer")
        print("=" * 60)
        self.parse_all()
        self.print_decoded_packets()
        mj_count = self.print_mousejack_decodes()
        self.build_histogram()
        print("\n=== Channel Occupancy Histogram ===")
        print(render_histogram(self.histogram))
        print(f"\n[+] Total packets: {len(self.decoded)}")
        print(f"[+] MouseJack HID decodes: {mj_count}")
        print(f"[+] Unique channels: {len(self.histogram)}")
        print("[+] Analysis complete — exit 0")
        return self.decoded


def main():
    observer = NRF24Observer()
    observer.run_analysis()
    return 0


if __name__ == "__main__":
    sys.exit(main())
