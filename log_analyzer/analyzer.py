"""One-pass aggregation of access log entries."""

import math
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from .parser import LogEntry, ParseError, parse_line


def percentile(sorted_values: List[float], q: float) -> float:
    """Nearest-rank percentile of an already sorted list (``q`` in 0..100)."""
    if not sorted_values:
        raise ValueError("no values")
    if not 0 <= q <= 100:
        raise ValueError("q must be between 0 and 100")
    rank = max(1, math.ceil(q / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


@dataclass
class Report:
    total: int
    malformed: int
    status_counts: Dict[int, int]
    status_classes: Dict[str, int]
    top_paths: List[Tuple[str, int]]
    top_ips: List[Tuple[str, int]]
    bytes_total: int
    latency_samples: int
    latency: Dict[str, float] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    slowest_paths: List[Tuple[str, float]] = field(default_factory=list)

    @property
    def error_rate(self) -> float:
        errors = self.status_classes.get("4xx", 0) + self.status_classes.get("5xx", 0)
        return errors / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "malformed": self.malformed,
            "status_counts": {str(k): v for k, v in sorted(self.status_counts.items())},
            "status_classes": dict(sorted(self.status_classes.items())),
            "error_rate": round(self.error_rate, 4),
            "top_paths": [{"path": p, "count": c} for p, c in self.top_paths],
            "top_ips": [{"ip": p, "count": c} for p, c in self.top_ips],
            "bytes_total": self.bytes_total,
            "latency_samples": self.latency_samples,
            "latency_seconds": self.latency,
            "slowest_paths_p95": [{"path": p, "p95": v} for p, v in self.slowest_paths],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class Analyzer:
    """Consumes entries one by one; memory does not grow with the number of lines.

    Counters grow with the number of distinct paths/IPs/statuses (not with the
    number of lines). Latency
    values are kept exactly up to ``max_latency_samples``; beyond that,
    reservoir sampling (Algorithm R) keeps a uniform sample, so percentiles
    become estimates while memory stays constant.
    """

    MAX_PATHS = 5000
    PATH_SAMPLES = 1000

    def __init__(self, top: int = 10, max_latency_samples: int = 100_000, seed: Optional[int] = 0):
        if top <= 0 or max_latency_samples <= 0:
            raise ValueError("top and max_latency_samples must be positive")
        self.top = top
        self._max_samples = max_latency_samples
        self._rng = random.Random(seed)
        self.total = 0
        self.malformed = 0
        self._status: Counter = Counter()
        self._paths: Counter = Counter()
        self._ips: Counter = Counter()
        self._bytes = 0
        self._latencies: List[float] = []
        self._latency_seen = 0
        self._path_latencies: Dict[str, list] = {}
        self._first: Optional[datetime] = None
        self._last: Optional[datetime] = None

    def add(self, entry: LogEntry) -> None:
        self.total += 1
        self._status[entry.status] += 1
        self._paths[entry.path] += 1
        self._ips[entry.ip] += 1
        self._bytes += entry.bytes_sent
        if self._first is None or entry.timestamp < self._first:
            self._first = entry.timestamp
        if self._last is None or entry.timestamp > self._last:
            self._last = entry.timestamp
        if entry.request_time is not None:
            self._add_latency(entry.request_time)
            self._add_path_latency(entry.path, entry.request_time)

    def _add_path_latency(self, path: str, value: float) -> None:
        # Per-path reservoir (at most PATH_SAMPLES values) for at most MAX_PATHS paths.
        slot = self._path_latencies.get(path)
        if slot is None:
            if len(self._path_latencies) >= self.MAX_PATHS:
                return
            slot = self._path_latencies[path] = [0, []]
        slot[0] += 1
        values = slot[1]
        if len(values) < self.PATH_SAMPLES:
            values.append(value)
        else:
            pos = self._rng.randrange(slot[0])
            if pos < self.PATH_SAMPLES:
                values[pos] = value

    def _add_latency(self, value: float) -> None:
        self._latency_seen += 1
        if len(self._latencies) < self._max_samples:
            self._latencies.append(value)
        else:
            slot = self._rng.randrange(self._latency_seen)
            if slot < self._max_samples:
                self._latencies[slot] = value

    def add_line(self, line: str) -> None:
        if not line.strip():
            return
        try:
            self.add(parse_line(line))
        except ParseError:
            self.malformed += 1

    def report(self) -> Report:
        classes: Counter = Counter()
        for status, n in self._status.items():
            classes[f"{status // 100}xx"] += n
        latency: Dict[str, float] = {}
        if self._latencies:
            ordered = sorted(self._latencies)
            latency = {
                "min": ordered[0],
                "p50": percentile(ordered, 50),
                "p95": percentile(ordered, 95),
                "p99": percentile(ordered, 99),
                "max": ordered[-1],
                "mean": round(sum(ordered) / len(ordered), 6),
            }
        slowest = sorted(
            (
                (path, percentile(sorted(vals), 95))
                for path, (_, vals) in self._path_latencies.items()
                if len(vals) >= 5
            ),
            key=lambda item: (-item[1], item[0]),
        )[: self.top]
        return Report(
            total=self.total,
            malformed=self.malformed,
            status_counts=dict(self._status),
            status_classes=dict(classes),
            top_paths=self._top(self._paths),
            top_ips=self._top(self._ips),
            bytes_total=self._bytes,
            latency_samples=len(self._latencies),
            latency=latency,
            first_seen=self._first,
            last_seen=self._last,
            slowest_paths=slowest,
        )

    def _top(self, counter: Counter) -> List[Tuple[str, int]]:
        # Sort by count desc, then name, so output is deterministic.
        return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[: self.top]


def analyze_lines(lines: Iterable[str], **kwargs) -> Report:
    analyzer = Analyzer(**kwargs)
    for line in lines:
        analyzer.add_line(line)
    return analyzer.report()
