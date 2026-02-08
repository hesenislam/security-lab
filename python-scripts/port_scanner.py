#!/usr/bin/env python3
# ======================================================
# Advanced Port Scanner (Educational / Lab Purpose)
# Author : Hesen Islamli
# Version: v5 - FINAL
# ======================================================

import socket
import threading
import argparse
from datetime import datetime
import json

# ---------------- CONFIG ----------------
TIMEOUT = 1
MAX_THREADS = 100
TXT_OUTPUT = "scan_results.txt"
JSON_OUTPUT = "scan_results.json"

COMMON_PORTS = {
    21:  ("FTP", "HIGH", "vsFTPd 2.3.4 vulnerable"),
    22:  ("SSH", "LOW", ""),
    23:  ("Telnet", "HIGH", "Plain-text authentication"),
    25:  ("SMTP", "LOW", ""),
    53:  ("DNS", "LOW", ""),
    80:  ("HTTP", "LOW", ""),
    110: ("POP3", "MEDIUM", ""),
    111: ("RPC", "LOW", ""),
    139: ("NetBIOS", "MEDIUM", ""),
    143: ("IMAP", "MEDIUM", ""),
    443: ("HTTPS", "LOW", ""),
    445: ("SMB", "MEDIUM", ""),
    512: ("rexec", "HIGH", "Deprecated remote execution"),
    513: ("rlogin", "HIGH", "Unencrypted login"),
    514: ("rsh", "HIGH", "Insecure remote shell"),
    3306: ("MySQL", "MEDIUM", "")
}

lock = threading.Lock()
results = []

# ---------------- FUNCTIONS ----------------
def grab_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return "No banner"

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        if sock.connect_ex((target, port)) == 0:
            banner = grab_banner(sock)

            service, risk, vuln = COMMON_PORTS.get(
                port, ("Unknown", "UNKNOWN", "")
            )

            result = {
                "port": port,
                "service": service,
                "risk": risk,
                "banner": banner,
                "vulnerability": vuln
            }

            with lock:
                results.append(result)

                print(
                    f"[+] Port {port:<5} OPEN | "
                    f"Service: {service:<10} | "
                    f"Risk: {risk:<7} | "
                    f"Banner: {banner}"
                )

                if vuln:
                    print(f"    ⚠ Possible issue: {vuln}")

        sock.close()

    except:
        pass

def save_txt(target, ports):
    with open(TXT_OUTPUT, "w") as f:
        f.write("Advanced Port Scanner Report\n")
        f.write("=" * 45 + "\n")
        f.write(f"Target : {target}\n")
        f.write(f"Ports  : {ports}\n")
        f.write(f"Date   : {datetime.now()}\n\n")

        for r in results:
            f.write(
                f"Port {r['port']} | "
                f"Service: {r['service']} | "
                f"Risk: {r['risk']} | "
                f"Banner: {r['banner']} | "
                f"Vuln: {r['vulnerability']}\n"
            )

def save_json(target, ports):
    report = {
        "target": target,
        "ports": ports,
        "date": str(datetime.now()),
        "results": results
    }

    with open(JSON_OUTPUT, "w") as f:
        json.dump(report, f, indent=4)

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner (Educational / Lab Use)",
        epilog="Example: python3 port_scanner.py -t 192.168.1.10 -p 1-1024"
    )

    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--json", action="store_true", help="Save output as JSON")

    args = parser.parse_args()

    target = args.target
    port_range = args.ports
    start_port, end_port = map(int, port_range.split("-"))

    print("\n[*] Target :", target)
    print(f"[*] Ports  : {start_port}-{end_port}")
    print("[*] Scan started...\n")

    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target, port))
        threads.append(t)
        t.start()

        if len(threads) >= MAX_THREADS:
            for th in threads:
                th.join()
            threads = []

    for th in threads:
        th.join()

    save_txt(target, port_range)

    if args.json:
        save_json(target, port_range)

    print("\n[✓] Scan completed successfully")
    print(f"[✓] TXT saved : {TXT_OUTPUT}")

    if args.json:
        print(f"[✓] JSON saved: {JSON_OUTPUT}")

# ---------------- RUN ----------------
if __name__ == "__main__":
    main()
