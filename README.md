# Simple Python Vulnerability Scanner

A lightweight, modular Python-based vulnerability scanner designed for educational penetration testing.

## Features
- Multi-threaded scanning of common ports
- CIDR range support (e.g. 192.168.1.0/24)
- Banner grabbing for service identification
- CVE lookup via both:
    - Offline NVD JSON data
    - Online CVE API
- JSON report generation
- Simple installer: `python3 setup.py`
- **NEW** Added GUI with debug window for ease of use

## Dependencies
- "Python 3.9+"
- "requests (This is installed during setup automatically)
- "tkinter - not included in all Linux installs, i.e. Arch. If missing, install via package manager.
```bash
sudo pacman -S tk 

or

sudo apt install python3-tk
```
## Getting Started

Instructions for terminal setup for headless setups.

```bash
git clone https://github.com/RamShackl/VulnScanner.git
cd VulnerabilityScanner
python3 setup.py
python3 main.py <target> -o report.json
```

## Disclaimer
**For educational use only. Do not use without permission**