import socket

target = input("Enter target IP or hostname: ")
ports = [21, 22, 23, 80, 443]

print(f"\nScanning target: {target}\n")

for port in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            print(f"Port {port} is OPEN")

        s.close()

    except KeyboardInterrupt:
        print("Scan interrupted")
        break
    except socket.gaierror:
        print("Hostname could not be resolved")
        break
    except socket.error:
        print("Could not connect to server")
        break
