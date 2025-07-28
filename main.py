import socket
import argparse

def scan_port(host, port):
    """Attempts to connect to a port and returns if it's open or closed."""
    try:
        print(f"Scanning port {port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 1 second timeout
            s.connect((host, port))
            s.send(b"")
            return True
    except socket.error as e:
        print(f"[-] Socket error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", required=False, help="Port range (e.g. 20-80)")
    parser.add_argument("--scan", required=False, help="Flag to scan all 65535 ports. Ignore if --ports is provided")
    parser.add_argument("--ignore-ephemeral", required=False, help="Ignore ephemeral ports (32768-65535). Only works with --scan.")
    args = parser.parse_args()

    host = args.host
    ports = args.ports
    scan = args.scan
    ignore_ephemeral = args.ignore_ephemeral

    if ports:
        try:
            start_port, end_port = map(int, args.ports.split("-"))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except ValueError:
            print("[-] Invalid port range. Use format like 20-80.")
            return

    elif scan:
        if ignore_ephemeral:
            start_port, end_port = (1, 32767)    
        else:
            start_port, end_port = (1, 65535)   

    else:
        print("[-] Must provide at least one of 'ports' or 'scan' arguments.")
        return

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[-] Cannot resolve hostname: {host}")
        return

    # Scan each port in range
    open_ports = []
    print(f"[+] Scanning {host} ({ip})")
    for port in range(start_port, end_port + 1):
        if scan_port(ip, port):
            open_ports.append(port)
    
    if len(open_ports) == 0:
        print("No port is OPEN")
        return

    for port in open_ports:
        print(f"Port {port} is OPEN")

if __name__ == "__main__":
    main()
