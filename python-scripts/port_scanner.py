#Port Scanner-Advanced(Educational purposes only)
#Author: Hasan Islamli
#Version:v4
import socket
import threading
from queue import Queue

# ---------------- CONFIG ----------------
TARGET = input("Target IP / Domain: ")
START_PORT = 1
END_PORT = 1024
THREAD_COUNT = 100
TIMEOUT = 1

# Known services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    3306: "MySQL",
    3389: "RDP"
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
    """Grab TCP banner"""
    try:
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return "No banner"


def grab_http_banner(target, port):
    """Grab HTTP Server header"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, port))

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: port-scanner\r\n"
            f"Connection: close\r\n\r\n"
        )

        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                return line

        return "HTTP server (no Server header)"
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

        print(
    f"[+] Port {port:<5} OPEN | "
    f"Service: {service:<10} | "
    f"Risk: {risk:<7} | "
    f"Banner: {banner}"
)


        sock.close()
    except:
        pass


def worker():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()

# ---------------- MAIN ----------------

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
