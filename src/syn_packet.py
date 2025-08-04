import asyncio
import os
import socket
import struct

TCP_HEADER_UNPACK_FORMAT = '!HHLLBBHHH'
TCP_SYN_ACK_FLAG = 0x18 # 18 = 00010010 --> (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
TCP_RST_FLAG = 0x04 # 4 = 00000100 --> (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)

def extract_tcp_flags_from(tcp_header):
    # H (2 bytes): Destination Port
    # L (4 bytes): Sequence Number
    # L (4 bytes): Acknowledgment Number
    # B (1 byte): Data Offset + Reserved (upper 4 bits: data offset, lower 4 bits: reserved)
    # B (1 byte): Flags (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    # H (2 bytes): Window Size
    # H (2 bytes): Checksum
    # H (2 bytes): Urgent Pointer
    
    # Check /raw_socket/tcp_header.png as reference
    # Consider it only cointains 6 flags
    flag_index = 5 # 6th field in unpacked TCP header
    return struct.unpack(TCP_HEADER_UNPACK_FORMAT, tcp_header)[flag_index]

def create_syn_packet(dst_ip, dst_port):
    """Create a SYN packet for scanning."""
    # IP header fields
    ip_version = 4                    # IPv4 version
    ip_ihl = 5                       # IP header length (5 * 4 = 20 bytes)
    ip_tos = 0                       # Type of service (0 = normal)
    ip_tot_len = 20 + 20             # Total length: IP header (20) + TCP header (20) -- 5 rows of 4 bytes = 20 bytes
    ip_id = 54321                    # Identification number (random)
    ip_frag_off = 0                  # Fragment offset (0 = no fragmentation)
    ip_ttl = 255                     # Time to live (255 = maximum)
    ip_proto = socket.IPPROTO_TCP    # Protocol (6 = TCP)
    ip_check = 0                     # Checksum (0 = calculated by kernel)
    ip_saddr = socket.inet_aton("127.0.0.1")  # Source IP address (localhost)
    ip_daddr = socket.inet_aton(dst_ip)       # Destination IP address
    
    # Combine version and header length into one byte
    ip_ver_ihl = (ip_version << 4) + ip_ihl
    
    # Pack IP header into binary format
    # Format: !BBHHHBBH4s4s = version/ihl, tos, tot_len, id, frag_off, ttl, proto, check, saddr, daddr
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    # TCP header fields
    tcp_sport = 12345                # Source port (random port)
    tcp_dport = dst_port             # Destination port (target port)
    tcp_seq = 0                      # Sequence number (0 = initial)
    tcp_ack_seq = 0                  # Acknowledgment number (0 = no ACK)
    tcp_doff = 5                     # Data offset (5 * 4 = 20 bytes header)
    tcp_fin = 0                      # FIN flag (0 = not set)
    tcp_syn = 1                      # SYN flag (1 = set for SYN scan)
    tcp_rst = 0                      # RST flag (0 = not set)
    tcp_psh = 0                      # PSH flag (0 = not set)
    tcp_ack = 0                      # ACK flag (0 = not set)
    tcp_urg = 0                      # URG flag (0 = not set)
    tcp_window = socket.htons(5840)  # Window size (network byte order)
    tcp_check = 0                    # Checksum (0 = calculated by kernel)
    tcp_urg_ptr = 0                  # Urgent pointer (0 = not used)
    
    # Combine data offset and reserved bits
    tcp_offset_res = (tcp_doff << 4) + 0
    
    # Combine all TCP flags into one byte
    # Flags: FIN(1) + SYN(2) + RST(4) + PSH(8) + ACK(16) + URG(32)
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    # Pack TCP header into binary format
    # Format: !HHLLBBHHH = sport, dport, seq, ack_seq, offset_res, flags, window, check, urg_ptr
    tcp_header = struct.pack('!HHLLBBHHH',
        tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
    
    # Combine IP and TCP headers to create complete packet
    return ip_header + tcp_header

def half_open_syn_single_port_async(host, port, timeout=1000):
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
        syn_packet = create_syn_packet(host, port)

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
                tcp_flags = extract_tcp_flags_from(tcp_header)
                
                # This indicates the port is open and accepting connections
                if tcp_flags == TCP_SYN_ACK_FLAG:
                    return port, True
                # This indicates the port is closed but reachable
                elif tcp_flags == TCP_RST_FLAG:
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

async def half_open_syn_scan_async(ip, start_port, end_port, timeout):
    open_ports = []
    tasks = []
    for port in range(start_port, end_port + 1):
        tasks.append(half_open_syn_single_port_async(ip, port, timeout))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for _, result in enumerate(results):
        if isinstance(result, tuple):
            port_num, is_open = result
            if is_open:
                open_ports.append(port_num)
    return open_ports