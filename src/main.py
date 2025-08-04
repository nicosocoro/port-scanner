import socket
import asyncio
import time
import args_parser
from scan_config import ScanConfig
import syn_packet as raw_socket

def scan_port(host, port, timeout=1000):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout / 1000)
            s.connect((host, port))
            s.send(b"")
            return port, True
    except socket.error:
        return port, False

async def full_tcp_scan_single_port_async(host, port, timeout=1000):
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

async def full_tcp_scan_async(host, start_port, end_port, config: ScanConfig):
    open_ports = []
    semaphore = asyncio.Semaphore(config.max_concurrent_scans)

    async def sem_scan(port):
        async with semaphore:
            return await full_tcp_scan_single_port_async(host, port, config.timeout)

    tasks = [sem_scan(port) for port in range(start_port, end_port + 1)]
    for task in asyncio.as_completed(tasks):
        try:
            port, is_open = await task
            if is_open:
                open_ports.append(port)
        except Exception:
            continue
    return open_ports

def main():
    config = args_parser.parse_args_to_config()
    
    try:
        if config.timeout <= 0:
            print("[-] Timeout must be greater than 0")
            return
    except ValueError:
        print("[-] Timeout must be a valid integer")
        return

    if config.ports:
        try:
            start_port, end_port = map(int, config.ports.split("-"))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except ValueError:
            print("[-] Invalid port range. Use format like 20-80.")
            return

    elif config.scan:
        if config.ignore_ephemeral:
            start_port, end_port = (1, 32767)    
        else:
            start_port, end_port = (1, 65535)   

    else:
        print("[-] Must provide at least one of 'ports' or 'scan' arguments.")
        return

    try:
        ip = socket.gethostbyname(config.host)
    except socket.gaierror:
        print(f"[-] Cannot resolve hostname: {config.host}")
        return

    # Scan ports
    print(f"[+] Scanning {config.host} ({ip})")
    print(f"[+] Port range: {start_port}-{end_port}")
    print(f"[+] Timeout: {config.timeout}ms")
    print("[+] Scan Type: " + ("Half open SYN" if config.syn_scan else "Full TCP"))

    start_time = time.time()
    
    open_ports = []
    if config.syn_scan:
        open_ports = asyncio.run(raw_socket.half_open_syn_scan_async(ip, start_port, end_port, config.timeout))
    else:
        open_ports = asyncio.run(full_tcp_scan_async(ip, start_port, end_port, config))
    
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
