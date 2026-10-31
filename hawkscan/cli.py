"""Command line interface for HawkScan."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys

from . import __version__
from .scanner import TOP_PORTS, ScanReport, parse_ports, scan_host

BANNER = r"""
  _   _                _     ____
 | | | | __ ___      _| | __/ ___|  ___ __ _ _ __
 | |_| |/ _` \ \ /\ / / |/ /\___ \ / __/ _` | '_ \
 |  _  | (_| |\ V  V /|   <  ___) | (_| (_| | | | |
 |_| |_|\__,_| \_/\_/ |_|\_\|____/ \___\__,_|_| |_|   v{version}
 TCP port scanner - use only on systems you own or are authorized to test
"""


def _color(enabled: bool):
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if enabled else text
    return paint


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hawkscan",
        description="Fast multithreaded TCP connect port scanner with banner grabbing.",
        epilog="Only scan systems you own or have explicit written permission to test.",
    )
    p.add_argument("target", help="hostname or IPv4 address (e.g. scanme.nmap.org, 127.0.0.1)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", help="ports: '22,80,443' or '1-1024' (default: 1-1024)")
    group.add_argument("--top", action="store_true", help="scan a shortlist of the most common ports")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per connection (default 1.0)")
    p.add_argument("-w", "--workers", type=int, default=100, help="concurrent threads (default 100)")
    p.add_argument("--no-banner", action="store_true", help="disable banner grabbing")
    p.add_argument("--show-all", action="store_true", help="also list closed/filtered ports")
    p.add_argument("-o", "--output", help="save report to a file (.json or .csv)")
    p.add_argument("-q", "--quiet", action="store_true", help="hide the ASCII banner")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def save_report(report: ScanReport, path: str) -> None:
    if path.lower().endswith(".csv"):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["port", "state", "service", "banner", "latency_ms"])
        for r in report.results:
            w.writerow([r.port, r.state, r.service, r.banner, r.latency_ms])
        content = buf.getvalue()
    else:
        content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)


def print_report(report: ScanReport, show_all: bool, paint) -> None:
    rows = report.results if show_all else report.open_ports
    print(f"\nScan report for {report.target} ({report.ip})")
    print(f"{'PORT':<10}{'STATE':<11}{'SERVICE':<16}INFO")
    for r in rows:
        color = {"open": "32", "closed": "31", "filtered": "33"}[r.state]
        state = paint(f"{r.state:<11}", color)
        print(f"{str(r.port) + '/tcp':<10}{state}{r.service:<16}{r.banner}")
    if not rows:
        print("No open ports found.")
    print(
        f"\n{len(report.open_ports)} open port(s) out of {report.ports_scanned} scanned "
        f"in {report.duration_s:.2f}s"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paint = _color(sys.stdout.isatty() and not args.no_color)

    if args.top:
        ports = sorted(TOP_PORTS)
    else:
        try:
            ports = parse_ports(args.ports or "1-1024")
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.timeout <= 0 or args.workers < 1:
        print("error: --timeout must be > 0 and --workers >= 1", file=sys.stderr)
        return 2

    if not args.quiet:
        print(paint(BANNER.format(version=__version__), "36"))

    try:
        report = scan_host(
            args.target,
            ports,
            timeout=args.timeout,
            workers=args.workers,
            banner=not args.no_banner,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130

    print_report(report, args.show_all, paint)

    if args.output:
        try:
            save_report(report, args.output)
        except OSError as exc:
            print(f"error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"Report saved to {args.output}")
    return 0
