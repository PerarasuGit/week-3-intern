
import socket
import csv
import argparse
from datetime import datetime
from ipaddress import ip_address, ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP"
}

DEFAULT_TIMEOUT = 1.0  # seconds
MAX_THREADS = 100      # concurrent threads for scanning

def is_port_open(ip, port, timeout=DEFAULT_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((str(ip), int(port)))
        return result == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def generate_risk_note(service):
    notes = {
        "FTP": "May allow anonymous access or weak passwords.",
        "SSH": "Check for weak credentials or outdated algorithms.",
        "TELNET": "Unencrypted remote shell - high risk.",
        "SMTP": "Open relay or exposed mail services possible.",
        "DNS": "Zone transfer or misconfiguration risk.",
        "HTTP": "Potential web app vulnerabilities (XSS, SQLi).",
        "POP3": "Plaintext credentials possible.",
        "IMAP": "Plaintext credentials possible.",
        "HTTPS": "Check TLS configuration and certificate validity.",
        "MySQL": "Database may be accessible; check auth.",
        "RDP": "Remote desktop exposed; brute-force risk."
    }
    return notes.get(service, "Review service configuration.")

def expand_targets(target_input):
    targets = []
    parts = [p.strip() for p in target_input.split(",") if p.strip()]
    for p in parts:
        if "/" in p:
            try:
                net = ip_network(p, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
            except Exception:
                continue
        elif "-" in p:
            # Range like 192.168.1.1-192.168.1.5
            try:
                start_str, end_str = p.split("-")
                start = int(ip_address(start_str))
                end = int(ip_address(end_str))
                for i in range(start, end+1):
                    targets.append(str(ip_address(i)))
            except Exception:
                continue
        else:
            try:
                ip_address(p)
                targets.append(p)
            except Exception:
                continue
    return targets

def scan_target_ports(ip, ports, timeout, workers):
    results = []
    # Build a list of (ip, port) to scan
    tasks = []
    for port in ports:
        tasks.append((ip, port))

    with ThreadPoolExecutor(max_workers=workers) as exe:
        future_to_task = {exe.submit(is_port_open, t[0], t[1], timeout): t for t in tasks}
        for future in as_completed(future_to_task):
            ip_addr, port = future_to_task[future]
            try:
                open_status = future.result()
            except Exception as e:
                open_status = False
            service = COMMON_PORTS.get(port, "unknown")
            status = "OPEN" if open_status else "CLOSED"
            risk = generate_risk_note(service) if open_status else "-"
            results.append({
                "ip": ip_addr,
                "port": port,
                "service": service,
                "status": status,
                "risk": risk
            })
    # sort by port for consistent output
    results.sort(key=lambda x: x["port"])
    return results

def save_csv(filename, rows):
    fieldnames = ["IP Address", "Port", "Service", "Status", "Risk Note"]
    with open(filename, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for r in rows:
            writer.writerow([r["ip"], r["port"], r["service"], r["status"], r["risk"]])

def main():
    parser = argparse.ArgumentParser(description="Port Scanner - Week 3 Intern Project")
    parser.add_argument("--targets", "-t", required=True,
                        help="Target IP(s). e.g. 127.0.0.1, 192.168.1.1-192.168.1.5, 192.168.1.0/30")
    parser.add_argument("--ports", "-p", default=",".join(str(x) for x in COMMON_PORTS.keys()),
                        help="Comma-separated ports to scan (default common set)")
    parser.add_argument("--timeout", help="Timeout in seconds per port (default 1.0)", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--out", "-o", help="Output CSV filename (default: scan_report_<timestamp>.csv)", default=None)
    parser.add_argument("--threads", "-T", type=int, default=20, help="Concurrent threads per target (default 20)")
    args = parser.parse_args()

    targets = expand_targets(args.targets)
    if not targets:
        print("No valid targets parsed. Exiting.")
        return
    try:
        port_list = [int(x.strip()) for x in args.ports.split(",") if x.strip().isdigit()]
    except Exception:
        print("Invalid ports list. Exiting.")
        return

    print(f"Starting scan of {len(targets)} target(s): {targets}")
    all_results = []
    start = datetime.now()
    for ip in targets:
        print(f"Scanning {ip} ...")
        res = scan_target_ports(ip, port_list, args.timeout, args.threads)
        all_results.extend(res)
    end = datetime.now()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    outname = args.out if args.out else f"scan_report_{timestamp}.csv"
    save_csv(outname, all_results)

    print(f"Scan complete. Results saved to {outname}")
    print(f"Time taken: {end - start}")

if __name__ == "__main__":
    main()
