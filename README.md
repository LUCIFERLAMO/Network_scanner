# 🔍 NetScan — ARP Network Scanner & Threat Detector

> Scan your local network, identify devices by vendor, detect intruders, and catch ARP spoofing attacks — all from the terminal.

![Python](https://img.shields.io/badge/Python-3.x-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Root Required](https://img.shields.io/badge/Requires-Root-red)

---

## Features

- 📡 ARP scan to discover all active devices on your network
- 🏷️ Vendor lookup using the IEEE OUI database
- 🆕 New/removed device detection (baseline comparison)
- 🚨 ARP spoofing detection (duplicate MACs + gateway MAC change)
- 💾 Export results to JSON

---

## Installation

```bash
git clone https://github.com/LUCIFERLAMO/netscan.git
cd netscan
pip install scapy rich requests
```

---

## Usage

```bash
sudo python3 netscan.py                        # auto-detects your subnet
sudo python3 netscan.py -i 192.168.1.0/24     # scan specific subnet
sudo python3 netscan.py -o results.json       # save output
sudo python3 netscan.py -c                    # detect new/removed devices
sudo python3 netscan.py -s                    # ARP spoof detection
sudo python3 netscan.py -i 192.168.1.0/24 -o results.json -c -s
```

---

## How It Works

| Function | What it does |
|---|---|
| `scan()` | Sends broadcast ARP requests and collects responses |
| `get_default_network()` | Auto-detects your subnet if no IP is given |
| `Download_OUI()` / `load_OUI()` | Downloads and caches the IEEE vendor database |
| `call_OUI()` | Looks up manufacturer from first 3 bytes of a MAC |
| `print_details()` | Prints results as a formatted table |
| `store_output()` | Saves IP, MAC, vendor to a JSON file |
| `save_baseline()` / `detect_changes()` | Snapshots the network and flags new or missing devices |
| `detect_arp_spoofing()` | Flags duplicate MACs and gateway MAC changes |

---

## License

MIT — This project is licensed under the [MIT License](LICENSE).
