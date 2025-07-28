import socket
import argparse

def scan_port(host, port):
    """Attempts to connect to a port and returns if it's open or closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 1 second timeout
            s.connect((host, port))
            s.send("")
            return True
    except socket.error as e:
        print(f"[-] Socket error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", required=True, help="Port range (e.g. 20-80)")
    args = parser.parse_args()

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[-] Cannot resolve hostname: {args.host}")
        return

    print(f"[+] Scanning {args.host} ({ip})")

    # Parse port range
    try:
        start_port, end_port = map(int, args.ports.split("-"))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print("[-] Invalid port range. Use format like 20-80.")
        return

    # Scan each port in range
    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            print(f"Port {port}: OPEN")
        else:
            print(f"Port {port}: CLOSED")

if __name__ == "__main__":
    main()
