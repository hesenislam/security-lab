# Advanced Port Scanner (Educational Purpose)
# Author: Hesen Islamli
# Version: v4

import socket
import threading
from queue import Queue

# ---------- CONFIG ----------
TARGET = input("Target IP / Domain: ")
START_PORT = 1
END_PORT = 1024
THREAD_COUNT = 100
TIMEOUT = 1

# Common services
COMMON_PORTS = {
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
    3306: "MySQL",
    3389: "RDP"
}

queue = Queue()
socket.setdefaulttimeout(TIMEOUT)

# ---------- FUNCTIONS ----------

def grab_banner(sock):
    try:
        return sock.recv(1024).decode().strip()
    except:
        return "No banner"
def grab_http_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))

        request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
        sock.send(request.encode())

        response = sock.recv(2048).decode(errors="ignore")
        sock.close()

        for line in response.split("\r\n"):
            if "Server:" in line:
                return line
        return "HTTP server (no Server header)"
    except:
        return "HTTP banner grab failed"


def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((TARGET, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            if port in [80, 443]:
    banner = grab_http_banner(TARGET, port)
else:
    banner = grab_banner(sock)

            print(f"[+] Port {port:<5} OPEN | Service: {service:<10} | Banner: {banner}")

        sock.close()
    except Exception as e:
        pass

def worker():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()

# ---------- MAIN ----------

print(f"\n[*] Scanning target: {TARGET}")
print(f"[*] Ports: {START_PORT}-{END_PORT}")
print("[*] Scanning started...\n")

for port in range(START_PORT, END_PORT + 1):
    queue.put(port)

for _ in range(THREAD_COUNT):
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()

queue.join()
print("\n[✓] Scan completed.")
