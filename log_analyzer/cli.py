"""Command line interface."""

import argparse
import json
import sys
from typing import List, Optional

from .analyzer import Analyzer, Report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="log_analyzer", description="Analyse nginx-style access logs")
    p.add_argument("files", nargs="*", help="log files; use '-' or no argument for stdin")
    p.add_argument("--top", type=int, default=10, help="rows in the top lists (default 10)")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--max-samples", type=int, default=100_000, help="latency reservoir size")
    return p


def format_report(r: Report) -> str:
    out = []
    out.append(f"Requests: {r.total}   malformed lines: {r.malformed}")
    if r.first_seen and r.last_seen:
        out.append(f"Period:   {r.first_seen.isoformat()}  ->  {r.last_seen.isoformat()}")
    out.append(f"Bytes:    {r.bytes_total}   error rate (4xx+5xx): {r.error_rate:.2%}")
    out.append("")
    out.append("Status codes")
    for status, n in sorted(r.status_counts.items()):
        out.append(f"  {status}  {n:>8}")
    out.append("")
    out.append("Top paths")
    for path, n in r.top_paths:
        out.append(f"  {n:>8}  {path}")
    out.append("")
    out.append("Top client IPs")
    for ip, n in r.top_ips:
        out.append(f"  {n:>8}  {ip}")
    if r.latency:
        out.append("")
        out.append(f"Latency in seconds ({r.latency_samples} samples)")
        for key in ("min", "p50", "p95", "p99", "max", "mean"):
            out.append(f"  {key:<5} {r.latency[key]:.3f}")
        if r.slowest_paths:
            out.append("")
            out.append("Slowest paths by p95 (at least 5 samples)")
            for path, value in r.slowest_paths:
                out.append(f"  {value:>8.3f}  {path}")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    analyzer = Analyzer(top=args.top, max_latency_samples=args.max_samples)
    sources = args.files or ["-"]
    for name in sources:
        if name == "-":
            for line in sys.stdin:
                analyzer.add_line(line)
        else:
            try:
                with open(name, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        analyzer.add_line(line)
            except OSError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
    report = analyzer.report()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
