# W5 — nRF24 Cross-Protocol Observer

Analysis suite for nRF24L01+ 2.4 GHz observation: ESB parsing, protocol decoding, channel-occupancy histograms, and MouseJack HID decodes.

## Overview

This project implements a standalone nRF24L01+ observation and analysis tool:
- Parses Enhanced ShockBurst (ESB) PDU byte streams from embedded sample captures
- Decodes address, payload, and control fields from promiscuous-mode captures
- Identifies nRF24 protocol lineage (CrazyRadio PA, Logitech Unifying)
- Builds a channel-occupancy histogram across the 2.4 GHz band
- Decodes MouseJack-style HID keyboard/mouse reports from known preamble patterns

## Features

- **ESB PDU Parser**: Extracts address, length, PID, no-ACK flag, and payload from raw bytes
- **Protocol Identification**: Recognizes CrazyRadio PA and Logitech Unifying preamble patterns
- **MouseJack HID Decoder**: Decodes modifier keys and keycodes from HID-over-nRF24 reports
- **Channel Occupancy Histogram**: Visual text-based bar chart of packet counts per channel
- **RSSI Tracking**: Records signal strength for each captured packet
- **Offline Demo**: Fully self-contained with embedded sample data, no hardware required

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 nrf_observer.py
```

## Usage

```bash
# Run full analysis demo (offline, embedded data)
python3 nrf_observer.py

# Programmatic usage
from nrf_observer import NRF24Observer, parse_esb_pdu, decode_mousejack_payload

observer = NRF24Observer()
observer.run_analysis()

# Parse a single PDU
pdu = bytes.fromhex("aabbccddee08003c...")
parsed = parse_esb_pdu(pdu)
```

## Example Output

```
============================================================
  W5 — nRF24 Cross-Protocol Observer
============================================================
[+] Parsing 20 ESB PDU captures...
[+] Decoded 20 packets

=== Decoded ESB Packets ===
  #  CH   RSSI Protocol             PID  Len Payload Hex
-------------------------------------------------------------------------------------
  0   2   -42dBm CrazyRadio PA        0   56 00010203040506070809...
  1   4   -55dBm CrazyRadio PA        0   56 00010203040506070809...
  2   6   -38dBm Logitech Unifying    1   56 00010203040506070809...
...

=== MouseJack HID Decodes ===
  CH 2 | ReportID=0 | Modifiers=[none] | Keys=[0, 1, 2, 3, 4, 5, 6, 7] | Raw=...
  CH 6 | ReportID=1 | Modifiers=[L-Ctrl] | Keys=[4, 5, 6] | Raw=...
...

=== Channel Occupancy Histogram ===
  CH | Count | Histogram
-------------------------------
   2 |     2 | ####
   4 |     2 | ####
   6 |     2 | ####
   8 |     2 | ####
  10 |     1 | ##
  12 |     1 | ##
...

[+] Total packets: 20
[+] MouseJack HID decodes: 10
[+] Unique channels: 16
[+] Analysis complete — exit 0
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the device owner before capturing nRF24 traffic
- Intercepting wireless communications on devices you do not own is illegal
- This tool should ONLY be used on devices you own or have written authorization to test
- nRF24 GPIO/SPI firmware for live capture is referenced in docs, not required here

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **FCC Regulations**: Operating nRF24L01+ hardware must comply with Part 15 regulations

### Acceptable Use
- Analyzing captured nRF24 traffic on your own devices
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Intercepting nRF24 communications on devices you don't own
- Injecting or replaying captured packets without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the device vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
