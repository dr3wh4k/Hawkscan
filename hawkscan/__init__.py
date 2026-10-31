"""HawkScan - a lightweight, dependency-free TCP port scanner."""

from .scanner import PortResult, ScanReport, parse_ports, scan_host, TOP_PORTS

__version__ = "1.0.0"
__all__ = ["PortResult", "ScanReport", "parse_ports", "scan_host", "TOP_PORTS", "__version__"]
