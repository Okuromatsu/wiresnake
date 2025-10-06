# Wiresnake

Wiresnake is a simple packet sniffer built in Python using **Scapy** and **Tkinter**.  
It provides a minimal graphical interface to capture, inspect, and save network packets, similar to a lightweight version of Wireshark.

---

## Features

- Live packet capture (TCP, UDP, ICMP, etc.)
- Basic BPF filtering (e.g. `tcp`, `udp or icmp`, `host 192.168.1.10`)
- Dark mode graphical interface
- Pause, resume, start, and stop capture
- Import and export `.pcap` files
- Packet details and hex view display

---

## Requirements

- Python 3.8+
- `scapy`
- `tkinter` (usually preinstalled)

Install dependencies:

```bash
pip install scapy tkinter
```
