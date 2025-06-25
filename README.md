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
- "requests 2.20.0"
- "tkinter" - Not default on Arch or lightweight Debian distros.
```bash
sudo pacman -S tk 

or

sudo apt install python3-tk
```
- "pyvis 0.2.1" - Specific version needed. Dunno why.
- jinja2 =0.3"

Dependencies are automatically installed with setup.py

## Getting Started

First, run the setup.py to download any dependencies.

Next, to run the program, python3 gui.py

## Instructions for terminal setup for headless setups.

```bash
git clone https://github.com/RamShackl/VulnScanner.git
cd VulnerabilityScanner
python3 setup.py
python3 main.py <target> -o report.json
```

arguments:

-v or --verbose for verbose
-f or --full-scan for a scan of ports 1-1024
-o or --output for a designated output file. report.json is default

## Disclaimer
**For educational use only. Do not use without permission**