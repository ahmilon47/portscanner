#!/usr/bin/env python3
"""
portscanner.py
Simple threaded TCP port scanner with optional banner grab.

Usage examples:
    python portscanner.py --host example.com --start 1 --end 1024
    python portscanner.py --host 192.168.1.10 --ports 22,80,443
    python portscanner.py --host example.com --common

Notes:
- This tool is for authorized testing only. Do not scan systems without permission.
- Uses only Python standard library (no extra pip packages required).
"""

import socket
import argparse
import concurrent.futures
import sys
import time

# Default timeout for socket connect (seconds)
SOCKET_TIMEOUT = 1.5

# Common ports list (small subset, extendable)
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,123,137,138,139,143,161,162,179,
    389,443,445,465,514,587,636,873,993,995,2049,3306,3389,5432,5900,6379,8080,8443
]


def parse_ports(ports_str):
    """Parse ports argument like '22,80,8000-8100'"""
    ports = set()
    parts = ports_str.split(',')
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            try:
                a, b = p.split('-', 1)
                a0 = int(a); b0 = int(b)
                ports.update(range(a0, b0 + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(p))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(host, port):
    """Try to read a small banner from an open socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            try:
                data = s.recv(1024)
                if data:
                    return data.decode(errors='replace').strip()
            except socket.timeout:
                return ""
            except Exception:
                return ""
    except Exception:
        return ""


def scan_port(host, port):
    """Return tuple (port, is_open, banner_or_err)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            res = s.connect_ex((host, port))
            if res == 0:
                banner = grab_banner(host, port)
                return (port, True, banner)
            else:
                return (port, False, "")
    except Exception as e:
        return (port, False, f"error:{e}")


def run_scan(host, ports, workers=100, show_closed=False):
    results = []
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_port = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(future_to_port):
            p = future_to_port[fut]
            try:
                port, is_open, info = fut.result()
                if is_open or show_closed:
                    results.append((port, is_open, info))
            except Exception as e:
                results.append((p, False, f"exception:{e}"))
    duration = time.time() - start_time
    results.sort(key=lambda x: x[0])
    return results, duration


def human_readable_results(results, host, duration):
    open_count = sum(1 for r in results if r[1])
    lines = []
    lines.append(f"Scan results for {host} — scanned {len(results)} ports in {duration:.2f}s — open: {open_count}")
    lines.append("=" * 70)
    for port, is_open, info in results:
        if is_open:
            line = f"[OPEN]  {port:<6} {info if info else ''}"
        else:
            line = f"[closed] {port:<6}"
        lines.append(line)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Simple threaded TCP Port Scanner")
    parser.add_argument("--host", "-H", required=True, help="Target host or IP")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--start", type=int, help="Start port (use with --end)")
    group.add_argument("--ports", help="Comma separated ports and ranges (e.g. 22,80,8000-8100)")
    group.add_argument("--common", action="store_true", help="Scan a list of common ports")
    parser.add_argument("--end", type=int, help="End port (use with --start)")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent worker threads (default 200)")
    parser.add_argument("--show-closed", action="store_true", help="Show closed ports in output")
    args = parser.parse_args()

    # Resolve host to IP
    try:
        ip = socket.gethostbyname(args.host)
    except Exception as e:
        print(f"Error resolving host '{args.host}': {e}")
        sys.exit(1)

    # Build port list
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.common:
        ports = COMMON_PORTS
    else:
        if args.start is None or args.end is None:
            print("When using --start you must also supply --end")
            sys.exit(1)
        s = max(1, args.start)
        e = min(65535, args.end)
        if e < s:
            print("End must be >= start")
            sys.exit(1)
        ports = list(range(s, e + 1))

    if not ports:
        print("No valid ports to scan.")
        sys.exit(1)

    print(f"Scanning {args.host} ({ip}) ports: {ports[0]}..{ports[-1]}  workers={args.workers}")
    results, duration = run_scan(ip, ports, workers=args.workers, show_closed=args.show_closed)
    print(human_readable_results(results, args.host, duration))


if __name__ == "__main__":
    main()