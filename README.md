# Port Scanner

This project is a solution for this challenge [The Challenge - Building A Network Port Scanner](https://codingchallenges.fyi/challenges/challenge-port-scanner/).

### Security Note - Disclaimer 

⚠️ **Important**: Only scan systems you own or have explicit permission to test. Unauthorized port scanning may be illegal in some jurisdictions.

This port scanner was built with the sole purpose of learning about TCP, Sockets and any related content.

## What is a Port Scanner?

A port scanner is a network security tool that examines a target system to identify which network ports are open, closed, or filtered. 

### Purpose and Use Cases

- **Network Security Assessment**: Identify potential vulnerabilities by finding open ports
- **Network Administration**: Verify which services are running on a system
- **Troubleshooting**: Diagnose network connectivity issues
- **Penetration Testing**: Ethical security testing to find weaknesses

### How Port Scanning Works

1. **Connection Attempt**: The scanner tries to establish a TCP connection to each port
2. **Response Analysis**: Based on the response, ports are classified as:
   - **Open**: Port accepts connections (service is running)
   - **Closed**: Port rejects connections (no service listening)
   - **Filtered**: No response received (likely blocked by firewall)

### Types of Port Scans

- **TCP Connect Scan**: Attempts full connection (most reliable)
- **SYN Scan**: Sends SYN packet without completing handshake
- **UDP Scan**: Scans UDP ports (less reliable than TCP)
- **Service Detection**: Identifies what service is running on open ports

## This Implementation

This is a basic TCP port scanner written in Python that performs connect scans.

### Features

- Scan specific port ranges (e.g., 20-80)
- SYN (Half open) scan
- Hostname resolution to IP address
- Timeout handling for faster scanning
- Clear output showing open/closed ports

#### SYN (Half open) scan

Only send SYN message from TCP handshake without establishing a full TCP three-way handshake.

It's faster and potentially bypasses basic firewall rules.

Possible responses from server:
* `SYN-ACK` (flags 0x12): Open and accepting connections   
* `RST` (flags 0x04): Closed port   
* Any other: Unexpected response

----

Code implemented in [src/syn_packet.py](./src/syn_packet.py).

This particular solution performs multiple port scanning asynchronously.

It's uses `Future` from [asyncio](https://docs.python.org/3/library/asyncio.html) and has a Future's coordination system
to avoid responses collisions.
Otherwise, at it happened at first, the multiple responses may not be properly handled and messed up among them.

For example, response from port 80 may be interpreted as response from port 81.

### Usage

```bash
cd src

# Scan a specific port range
python main.py --host example.com --ports 20-80

# Scan common ports
python main.py --host 192.168.1.1 --ports 1-1024

# SYN scan
python main.py --host 192.168.1.1 --ports 1-1024 --syn
```

### Example Output

```
[+] Scanning example.com (93.184.216.34)
Port 20: CLOSED
Port 21: CLOSED
Port 22: OPEN
Port 23: CLOSED
...
```

## Common Ports

| Port | Service | Description |
|------|---------|-------------|
| 21   | FTP     | File Transfer Protocol |
| 22   | SSH     | Secure Shell |
| 23   | Telnet  | Remote terminal access |
| 25   | SMTP    | Email sending |
| 53   | DNS     | Domain Name System |
| 80   | HTTP    | Web browsing |
| 443  | HTTPS   | Secure web browsing |
| 3306 | MySQL   | Database |
| 5432 | PostgreSQL | Database |

## Dependencies

- Python 3.x
- Standard library modules: `socket`, `argparse`

No additional packages required! 