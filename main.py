import socket
import argparse
import asyncio
import time

def scan_port(host, port, timeout=1000):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout / 1000)
            s.connect((host, port))
            s.send(b"")
            return port, True
    except socket.error:
        return port, False

async def scan_port_async(host, port, timeout=1000):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout / 1000
        )
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, OSError):
        return port, False

async def scan_ports_async(host, start_port, end_port, timeout=1000):
    open_ports = []

    tasks = [scan_port_async(host, port, timeout) for port in range(start_port, end_port + 1)]
    
    for task in asyncio.as_completed(tasks):
        try:
            port, is_open = await task
            if is_open:
                open_ports.append(port)
        except Exception:
            continue
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", required=False, help="Port range (e.g. 20-80)")
    parser.add_argument("--scan", required=False, help="Flag to scan all 65535 ports. Ignore if --ports is provided")
    parser.add_argument("--ignore-ephemeral", action="store_true", help="Ignore ephemeral ports (32768-65535). Only works with --scan.")
    parser.add_argument("--timeout", required=False, default=1000, help="Timeout in milliseconds to analyze a port.")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel scanning for maximum performance.")
    args = parser.parse_args()

    host = args.host
    ports = args.ports
    scan = args.scan
    ignore_ephemeral = args.ignore_ephemeral
    timeout = args.timeout
    parallel_scan = getattr(args, 'parallel', False)
    
    try:
        timeout = int(timeout)
        if timeout <= 0:
            print("[-] Timeout must be greater than 0")
            return
    except ValueError:
        print("[-] Timeout must be a valid integer")
        return

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

    # Scan ports
    print(f"[+] Scanning {host} ({ip})")
    print(f"[+] Port range: {start_port}-{end_port}")
    print(f"[+] Timeout: {timeout}ms")
    
    start_time = time.time()
    
    open_ports = []
    if parallel_scan:
        print(f"[+] Parallel scanning")
        open_ports = asyncio.run(scan_ports_async(ip, start_port, end_port, timeout))
    else:
        print("[+] Sequential scanning")
        for port in range(start_port, end_port + 1):
            port_num, is_open = scan_port(ip, port, timeout)
            if is_open:
                open_ports.append(port_num)
                print(f"Port {port_num}: OPEN")
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")

    if len(open_ports) == 0:
        print("\nNo port is OPEN")
    else:
        print(f"\n[+] Summary: {len(open_ports)} open ports found")
        for port in sorted(open_ports):
            print(f"  - Port {port}: OPEN")
    

if __name__ == "__main__":
    main()
