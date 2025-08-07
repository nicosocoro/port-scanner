import asyncio
import os
import socket
import struct
import random

class SYNScanner:

    TCP_HEADER_UNPACK_FORMAT = '!HHLLBBHHH'
    TCP_SYN_ACK_FLAG = 0x12 # 12 = 0001 0010 --> (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    TCP_RST_FLAG = 0x04 # 4 = 0000 0100 --> (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    
    def __init__(self):
        self.pending_requests = {} 
        self.raw_socket = None
        self.receiver_task = None

    async def __aenter__(self):
        """Initialize when use 'async with'."""
        # Check privileges
        if os.geteuid() != 0:
            raise PermissionError("SYN scan requires root privileges. Use sudo.")
        
        # Create raw socket
        self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.raw_socket.setblocking(False)
        
        # Start receiver task
        self.receiver_task = asyncio.create_task(self._receive_responses())
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up when use 'async with'."""
        if self.receiver_task:
            self.receiver_task.cancel()
            try:
                await self.receiver_task
            except asyncio.CancelledError:
                pass
        
        if self.raw_socket:
            self.raw_socket.close()

    async def scan_port(self, host, dst_port, timeout):
        """Scan a port using SYN packet (requires root privileges)."""
        try:
            src_port = random.randint(32768, 65535)
            syn_packet = self.create_syn_packet(host, dst_port, src_port)
            self.raw_socket.sendto(syn_packet, (host, 0))

            request_key = (src_port, dst_port)
            future = asyncio.Future()
            self.pending_requests[request_key] = future

            try:
                # Listen for response from the target
                result = await asyncio.wait_for(future, timeout=timeout)
                return dst_port, result
            
            except socket.timeout:
                print(f"[-] Timeout while waiting for response from {host}:{dst_port}")
                self.raw_socket.close()
                return dst_port, False
        except (socket.error, PermissionError) as e:
            print(f"[-] Error in SYN scan: {e}")
            return dst_port, False
        except Exception as e:
            print(f"[-] Unexpected error in SYN scan: {e}")
            return dst_port, False

    def create_syn_packet(self, dst_ip, dst_port, src_port):
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
        ip_check = 0                     # Checksum (0 = calculated later)
        
        # Get the actual local IP address for the outgoing packet
        try:
            # This gets the default outbound IP for the destination
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_sock.connect((dst_ip, 0))
            local_ip = temp_sock.getsockname()[0]
            temp_sock.close()
        except Exception:
            local_ip = "127.0.0.1"  # Fallback if unable to determine

        ip_saddr = socket.inet_aton(local_ip)  # Source IP address (actual local IP)
        ip_daddr = socket.inet_aton(dst_ip)    # Destination IP address
        
        # Combine version and header length into one byte
        ip_ver_ihl = (ip_version << 4) + ip_ihl
        
        # Pack IP header into binary format
        # Format: !BBHHHBBH4s4s = version/ihl, tos, tot_len, id, frag_off, ttl, proto, check, saddr, daddr
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        
        ip_check = self.checksum(ip_header)

        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        
        # TCP header fields
        tcp_sport = src_port          # Source port (random port)
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
        tcp_ece = 0                      # ECE flag (0 = not set)
        tcp_cwr = 0                      # CWR flag (0 = not set)
        tcp_window = socket.htons(5840)  # Window size (network byte order)
        tcp_check = 0                    # Checksum (0 = calculated later)
        tcp_urg_ptr = 0                  # Urgent pointer (0 = not used)

        # Combine data offset and reserved bits
        tcp_offset_res = (tcp_doff << 4) + 0

        # Combine all TCP flags into one byte (8 bits)
        # Flags: FIN(1) + SYN(2) + RST(4) + PSH(8) + ACK(16) + URG(32) + ECE(64) + CWR(128)
        tcp_flags = (tcp_fin << 0) | (tcp_syn << 1) | (tcp_rst << 2) | (tcp_psh << 3) | (tcp_ack << 4) | (tcp_urg << 5) | (tcp_ece << 6) | (tcp_cwr << 7)

        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        pseudo_header = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
        checksum_data = pseudo_header + tcp_header
        tcp_check = self.checksum(checksum_data)

        # Pack TCP header into binary format
        # Format: !HHLLBBHHH = sport, dport, seq, ack_seq, offset_res, flags, window, check, urg_ptr
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # Combine IP and TCP headers to create complete packet
        return ip_header + tcp_header

    def checksum(self, data):
        if len(data) % 2:
            data += b'\x00'  # pad if not even
        s = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            s += word
            s = (s & 0xffff) + (s >> 16)  # carry around
        return ~s & 0xffff

    async def _receive_responses(self):
        loop = asyncio.get_running_loop()

        while True:
            try:
                response = await loop.run_in_executor(
                    None, lambda: self.raw_socket.recvfrom(1024)
                )
                data, _ = response
                
                if len(data) >= 40:
                    tcp_header = data[20:40]
                    src_port, dst_port, _, _, flags_etc = struct.unpack('!HHLLH', tcp_header[:14])
                    tcp_flags = flags_etc & 0xFF # 0xFF to only get the flags byte, ignoring offset and reserved bits

                    request_key = (dst_port, src_port) # Swap to match the request key format.

                    if request_key in self.pending_requests:
                        future = self.pending_requests[request_key]
                        
                        if not future.done():
                            if tcp_flags == self.TCP_SYN_ACK_FLAG:
                                future.set_result(True)
                            elif tcp_flags == self.TCP_RST_FLAG:
                                future.set_result(False)
                            else:
                                future.set_result(False)
                                
                        del self.pending_requests[request_key]
                else:
                    print(f"[-] Received invalid response: {response} of length {len(response)}")
                
            except socket.error:
                # Socket might be closed or no data available
                await asyncio.sleep(0.001)
            except Exception as e:
                print(f"Error in receiver: {e}")
                await asyncio.sleep(0.001)