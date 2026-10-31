"""Core scanning engine: multithreaded TCP connect scan with banner grabbing."""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Optional

# Most common TCP ports (curated shortlist, similar in spirit to nmap --top-ports).
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
]

HTTP_PORTS = {80, 8000, 8080, 8008, 8888}

_CLOSED_ERRNOS = {errno.ECONNREFUSED, 10061}


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = "unknown"
    banner: str = ""
    latency_ms: Optional[float] = None


@dataclass
class ScanReport:
    target: str
    ip: str
    started_at: str
    duration_s: float
    ports_scanned: int
    results: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == "open"]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "ports_scanned": self.ports_scanned,
            "results": [asdict(r) for r in self.results],
        }


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification such as ``"22,80,443"`` or ``"1-1024,8080"``."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:
                    raise ValueError(f"invalid range '{part}'")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError as exc:
            raise ValueError(f"invalid port specification '{part}'") from exc
    if not ports:
        raise ValueError("no ports specified")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Try to read a short service banner from an already connected socket."""
    try:
        sock.settimeout(timeout)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(256)
    except OSError:
        return ""
    lines = data.decode(errors="replace").strip().splitlines()
    return lines[0][:120] if lines else ""


def scan_port(host: str, ip: str, port: int, timeout: float = 1.0, banner: bool = True) -> PortResult:
    """Scan one TCP port using a full connect() and classify its state."""
    svc = service_name(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        code = sock.connect_ex((ip, port))
        elapsed = (time.perf_counter() - start) * 1000
        if code == 0:
            text = grab_banner(sock, host, port, min(timeout, 1.0)) if banner else ""
            return PortResult(port, "open", svc, text, round(elapsed, 2))
        state = "closed" if code in _CLOSED_ERRNOS else "filtered"
        return PortResult(port, state, svc, "", round(elapsed, 2))
    except OSError:  # includes socket.timeout
        return PortResult(port, "filtered", svc)
    finally:
        sock.close()


def scan_host(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
    banner: bool = True,
    on_result: Optional[Callable[[PortResult], None]] = None,
) -> ScanReport:
    """Scan ``ports`` on ``target`` concurrently and return a :class:`ScanReport`."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve host '{target}'") from exc

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.perf_counter()
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(scan_port, target, ip, p, timeout, banner) for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if on_result:
                on_result(res)

    results.sort(key=lambda r: r.port)
    return ScanReport(target, ip, started, time.perf_counter() - t0, len(ports), results)
