import argparse
import scan_config

def parse_args_to_config():
    parser = argparse.ArgumentParser(description="Basic TCP Port Scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    parser.add_argument("--ports", required=False, help="Port range (e.g. 20-80)")
    parser.add_argument("--scan", required=False, help="Flag to scan all 65535 ports. Ignore if --ports is provided")
    parser.add_argument("--ignore-ephemeral", action="store_true", help="Ignore ephemeral ports (32768-65535). Only works with --scan.")
    parser.add_argument("--timeout", required=False, default=1000, help="Timeout in milliseconds to analyze a port.")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel scanning for maximum performance.")
    parser.add_argument("--syn", action="store_true", help="Use SYN scan (requires root privileges).")
    args = parser.parse_args()
    
    return scan_config.ScanConfig(
        host=args.host,
        ports=args.ports,
        scan=args.scan,
        ignore_ephemeral=args.ignore_ephemeral,
        timeout=args.timeout,
        parallel_scan=getattr(args, 'parallel', False),
        syn_scan=args.syn
    )