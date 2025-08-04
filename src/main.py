import socket
import asyncio
import time
import struct
import os
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
                tcp_flags = syn_packet.extract_tcp_flags_from(tcp_header)
                
                # This indicates the port is open and accepting connections
                if tcp_flags == syn_packet.TCP_SYN_ACK_FLAG:
                    return port, True
                # This indicates the port is closed but reachable
                elif tcp_flags == syn_packet.TCP_RST_FLAG:
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
    config = args_parser.parse_args_to_config()
    
    try:
        timeout = int(config.timeout)
        if timeout <= 0:
            print("[-] Timeout must be greater than 0")
            return
    except ValueError:
        print("[-] Timeout must be a valid integer")
        return

    if config.ports:
        try:
            start_port, end_port = map(int, args.ports.split("-"))
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
    print(f"[+] Timeout: {timeout}ms")
    
    start_time = time.time()
    
    open_ports = []
    if config.syn_scan:
        print("[+] SYN scanning (requires root privileges)")
        for port in range(start_port, end_port + 1):
            port_num, is_open = scan_port_syn(ip, port, timeout)
            if is_open:
                open_ports.append(port_num)
                print(f"Port {port_num}: OPEN")
    elif config.parallel_scan:
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
