# Advanced Port Scanner (Educational Purpose)
# Author: Hesen Islamli
# Version: v3

import socket

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        return result == 0
    except:
        return False

def main():
    target = input("Enter target IP or hostname: ")

    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
    except ValueError:
        print("Invalid port number.")
        return

    print(f"\nScanning {target} from port {start_port} to {end_port}\n")

    for port in range(start_port, end_port + 1):
        if scan_port(target, port):
            print(f"[OPEN] Port {port}")

if __name__ == "__main__":
    main()

