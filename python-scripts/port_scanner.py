# Port Scanner - Advanced (Educational purposes only)
# Author: Hasan Islamli
# Version: v4
import argparse
import socket
import threading
import datetime
from queue import Queue

# ---------------- CONFIG ----------------
parser = argparse.ArgumentParser(
    description="Advanced Port Scanner (Educational purposes only)"
)

parser.add_argument(
    "-t", "--target",
    required=True,
    help="Target IP or domain"
)

parser.add_argument(
    "-p", "--ports",
    default="1-1024",
    help="Port range (default: 1-1024)"
)

parser.add_argument(
    "--threads",
    type=int,
    default=100,
    help="Number of threads (default: 100)"
)

args = parser.parse_args()

TARGET = args.target
THREAD_COUNT = args.threads

# Port range parsing
try:
    START_PORT, END_PORT = map(int, args.ports.split("-"))
except:
    print("[!] Invalid port range format. Example: 1-1000")
    exit()


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 512: "rexec", 513: "rlogin",
    514: "rsh", 3306: "MySQL", 3389: "RDP"
}

RISK_LEVELS = {
    "FTP": "HIGH",
    "Telnet": "HIGH",
    "rexec": "HIGH",
    "rlogin": "HIGH",
    "rsh": "HIGH",
    "SMB": "MEDIUM",
    "NetBIOS": "MEDIUM",
    "HTTP": "LOW",
    "SSH": "LOW",
    "SMTP": "LOW",
    "RPC": "LOW"
}

queue = Queue()
socket.setdefaulttimeout(TIMEOUT)

# ---------------- FUNCTIONS ----------------

def grab_banner(sock):
    try:
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return "No banner"


def grab_http_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n\r\n"
        )

        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                return line

        return "HTTP server (no header)"
    except:
        return "HTTP banner grab failed"


def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((TARGET, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            risk = RISK_LEVELS.get(service, "UNKNOWN")

            if port in [80, 443]:
                banner = grab_http_banner(TARGET, port)
            else:
                banner = grab_banner(sock)

            message = (
                f"[+] Port {port:<5} OPEN | "
                f"Service: {service:<10} | "
                f"Risk: {risk:<7} | "
                f"Banner: {banner}"
            )

            print(message)
            output.write(message + "\n")

        sock.close()

    except Exception as e:
        error_time = datetime.datetime.now()
        with open("error.log", "a") as err:
            err.write(f"[{error_time}] Port {port} error: {e}\n")


def worker():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()

# ---------------- MAIN ----------------
# ---------------- MAIN ----------------

output = open(OUTPUT_FILE, "w")
output.write(f"Scan Target: {TARGET}\n")
output.write(f"Ports: {START_PORT}-{END_PORT}\n")
output.write(f"Threads: {THREAD_COUNT}\n")
output.write("=" * 50 + "\n")

print(f"\n[*] Scanning target: {TARGET}")
print(f"[*] Ports: {START_PORT}-{END_PORT}")
print(f"[*] Threads: {THREAD_COUNT}")
print("[*] Scanning started...\n")

try:
    for port in range(START_PORT, END_PORT + 1):
        queue.put(port)

    for _ in range(THREAD_COUNT):
        threading.Thread(target=worker, daemon=True).start()

    queue.join()
    print("\n[✓] Scan completed.")

except KeyboardInterrupt:
    print("\n[!] Scan interrupted by user (Ctrl+C)")

finally:
    output.close()
    print(f"[✓] Results saved to {OUTPUT_FILE}")
