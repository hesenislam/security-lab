# scanner.py
# ==========================================
# Core Port Scanning Engine
# Author : Hesen Islamli
# ==========================================

import socket
import threading

TIMEOUT = 1
MAX_THREADS = 100

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


def grab_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return "No banner"


def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        if sock.connect_ex((target, port)) == 0:
            banner = grab_banner(sock)
            service, risk, vuln = COMMON_PORTS.get(
                port, ("Unknown", "UNKNOWN", "")
            )

            with lock:
                results.append({
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "banner": banner,
                    "vulnerability": vuln
                })

        sock.close()
    except:
        pass


def scan(target, start_port, end_port):
    """
    Main scanning function
    Returns list of open ports with metadata
    """
    results = []
    threads = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(
            target=scan_port,
            args=(target, port, results)
        )
        threads.append(t)
        t.start()

        if len(threads) >= MAX_THREADS:
            for th in threads:
                th.join()
            threads = []

    for th in threads:
        th.join()

    return sorted(results, key=lambda x: x["port"])
