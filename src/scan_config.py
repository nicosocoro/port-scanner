class ScanConfig:
    def __init__(self, host, ports, scan, ignore_ephemeral, timeout, sequential_scan, syn_scan):
        self.host = host
        self.ports = ports
        self.scan = scan
        self.ignore_ephemeral = ignore_ephemeral
        self.timeout = timeout
        self.sequential_scan = sequential_scan
        self.syn_scan = syn_scan