# PortScanner — Simple Threaded TCP Port Scanner

A minimal, educational port scanner written in Python (standard library only).  
Use it to learn network scanning and banner grabbing in a safe, local environment.

## Features
- Threaded TCP port scanning (fast)
- Parse ports like `22,80,8000-8100`
- Quick banner grab for open ports (best-effort)
- No external dependencies (only Python standard library)

## Requirements
- Python 3.8+

## How to run
```bash
# go to project folder
cd "C:/Users/HP/OneDrive/Desktop/python"

# Examples:
python portscanner.py --host 127.0.0.1 --common
python portscanner.py --host scanme.nmap.org --ports 22,80,443
python portscanner.py --host 192.168.1.1 --start 1 --end 1024 --workers 200