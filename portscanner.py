# portscanner.py (Upgraded Version)
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import datetime
import re

# ------------------------
# Service Detection (basic)
# ------------------------
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

# ------------------------
# Scan a single port
# ------------------------
def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(s)
                service = SERVICE_PORTS.get(port, "Unknown")
                return {"port": port, "state": "Open", "banner": banner, "service": service}
            else:
                return {"port": port, "state": "Closed", "banner": None, "service": None}
    except Exception:
        return {"port": port, "state": "Filtered", "banner": None, "service": None}

# ------------------------
# Banner grab
# ------------------------
def grab_banner(sock):
    try:
        sock.send(b'Hello\r\n')
        banner = sock.recv(1024).decode().strip()
        return banner
    except Exception:
        return None

# ------------------------
# Scan multiple ports
# ------------------------
def scan_ports(host, ports, workers=100):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, host, port) for port in ports]
        for future in futures:
            results.append(future.result())
    return results

# ------------------------
# Save scan report as JSON
# ------------------------
def save_report(host, results, filename=None):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "host": host,
        "timestamp": timestamp,
        "results": results
    }
    if filename is None:
        filename = f"scan_{host}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Scan report saved as {filename}")

# ------------------------
# Argument parsing
# ------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Upgraded Python Port Scanner with Banner Grab & Service Detection")
    parser.add_argument("--host", help="Target host IP or domain")
    parser.add_argument("--interactive", action="store_true", help="Enable interactive mode")
    parser.add_argument("--ports", help="Comma-separated list of ports to scan (e.g., 22,80,443)")
    parser.add_argument("--start", type=int, help="Start port for range scan")
    parser.add_argument("--end", type=int, help="End port for range scan")
    parser.add_argument("--common", action="store_true", help="Scan common ports only")
    parser.add_argument("--workers", type=int, default=200, help="Number of concurrent workers")
    parser.add_argument("--save", action="store_true", help="Save scan report as JSON")
    return parser.parse_args()

# ------------------------
# Interactive mode
# ------------------------
def interactive_mode():
    host = input("Enter host to scan: ").strip()
    choice = input("Scan common ports, custom ports, or range? [common/custom/range]: ").strip().lower()
    ports = []
    if choice == "common":
        ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
    elif choice == "custom":
        ports_input = input("Enter comma-separated ports: ").strip()
        ports = [int(p.strip()) for p in ports_input.split(",")]
    elif choice == "range":
        start = int(input("Start port: ").strip())
        end = int(input("End port: ").strip())
        ports = list(range(start, end+1))
    else:
        print("Invalid choice!")
        return host, ports
    return host, ports

# ------------------------
# Main
# ------------------------
def main():
    args = parse_args()

    if args.interactive:
        host, ports = interactive_mode()
    else:
        host = args.host
        if args.common:
            ports = [21,22,23,25,53,80,110,139,143,443,445,3389]
        elif args.ports:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        elif args.start and args.end:
            ports = list(range(args.start, args.end+1))
        else:
            print("Error: specify --interactive, --common, --ports, or --start/--end")
            return

    print(f"Scanning {host} ports: {ports}  workers={args.workers}")
    results = scan_ports(host, ports, args.workers)

    # Print results
    for r in results:
        if r["state"] == "Open":
            banner_str = f" | Banner: {r['banner']}" if r['banner'] else ""
            service_str = f" | Service: {r['service']}" if r['service'] else ""
            print(f"[{r['port']}] Open{service_str}{banner_str}")
        else:
            print(f"[{r['port']}] {r['state']}")

    # Save report
    if args.save:
        save_report(host, results)

if __name__ == "__main__":
    main()