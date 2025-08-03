import socket
import argparse
import asyncio
import time
import struct
import os
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

def scan_port_syn(host, port, timeout=1000):
    """Scan a port using SYN packet (requires root privileges)."""
    try:
        # Check if running as root (raw sockets require elevated privileges)
        if os.geteuid() != 0:
            print("[-] SYN scan requires root privileges. Use sudo.")
            return port, False
        
        # Create raw socket for custom packet manipulation
        # AF_INET = IPv4, SOCK_RAW = raw socket, IPPROTO_TCP = TCP protocol
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout / 1000)  # Set timeout in seconds
        
        # Create custom SYN packet with our own IP and TCP headers
        syn_packet = raw_socket.create_syn_packet(host, port)

        # Send the raw packet to the target host
        # (host, 0) = destination address, port 0 (not used for raw sockets)
        s.sendto(syn_packet, (host, 0))
        
        # Listen for response from the target
        try:
            # Receive response packet (max 1024 bytes)
            response, _ = s.recvfrom(1024)
            
            # Parse the response packet
            if len(response) >= 40:  # Ensure we have IP header (20) + TCP header (20)
                # Extract TCP header from response (bytes 20-39)
                tcp_header = response[20:40]
                # Unpack TCP header and get flags (6th field)
                tcp_flags = struct.unpack('!BBHHLLBBHHH', tcp_header)[6]
                
                # Check for SYN-ACK response (flags = 18 = SYN + ACK)
                # This indicates the port is open and accepting connections
                if tcp_flags == 18:
                    return port, True
                # Check for RST response (flags = 4)
                # This indicates the port is closed but reachable
                elif tcp_flags == 4:
                    return port, False
        except socket.timeout:
            # No response received within timeout period
            return port, False
        
        # Close the raw socket
        s.close()
        return port, False
        
    except (socket.error, PermissionError) as e:
        # Handle socket errors and permission errors
        print(f"[-] Error in SYN scan: {e}")
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
    parser.add_argument("--syn", action="store_true", help="Use SYN scan (requires root privileges).")
    args = parser.parse_args()

    host = args.host
    ports = args.ports
    scan = args.scan
    ignore_ephemeral = args.ignore_ephemeral
    timeout = args.timeout
    parallel_scan = getattr(args, 'parallel', False)
    syn_scan = args.syn
    
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
    if syn_scan:
        print("[+] SYN scanning (requires root privileges)")
        for port in range(start_port, end_port + 1):
            port_num, is_open = scan_port_syn(ip, port, timeout)
            if is_open:
                open_ports.append(port_num)
                print(f"Port {port_num}: OPEN")
    elif parallel_scan:
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
