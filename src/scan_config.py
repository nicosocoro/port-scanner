class ScanConfig:
    def __init__(self, host, ports, scan, ignore_ephemeral, timeout, syn_scan):
        self.host = host
        self.ports = ports
        self.scan = scan
        self.ignore_ephemeral = ignore_ephemeral
        self.timeout = int(timeout)
        self.syn_scan = syn_scan
        self.max_concurrent_scans = 1000