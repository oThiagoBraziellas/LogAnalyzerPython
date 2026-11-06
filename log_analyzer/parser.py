"""Parser for the nginx ``combined`` format with an optional request time.

Expected line::

    1.2.3.4 - user [10/Oct/2026:13:55:36 +0000] "GET /a?x=1 HTTP/1.1" 200 512 "ref" "agent" 0.123

The trailing request time (seconds, as in ``$request_time``) may be quoted or
bare and may be missing; the referer and user agent are optional too, so the
common log format also parses.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

_LINE = re.compile(
    r"""^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+
        \[(?P<time>[^\]]+)\]\s+
        "(?P<request>(?:[^"\\]|\\.)*)"\s+
        (?P<status>\d{3})\s+
        (?P<bytes>\d+|-)
        (?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"
           \s+"(?P<agent>(?:[^"\\]|\\.)*)")?
        (?:\s+"?(?P<rt>\d+(?:\.\d+)?)"?)?
        \s*$""",
    re.VERBOSE,
)

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ParseError(ValueError):
    """The line does not look like an access log entry."""


@dataclass(frozen=True)
class LogEntry:
    ip: str
    user: str
    timestamp: datetime
    method: str
    path: str  # without the query string
    protocol: str
    status: int
    bytes_sent: int
    referer: Optional[str]
    user_agent: Optional[str]
    request_time: Optional[float]  # seconds


def parse_line(line: str) -> LogEntry:
    match = _LINE.match(line.rstrip("\r\n"))
    if match is None:
        raise ParseError(f"unrecognised line: {line[:80]!r}")
    try:
        timestamp = datetime.strptime(match["time"], _TIME_FORMAT)
    except ValueError as exc:
        raise ParseError(f"bad timestamp: {match['time']!r}") from exc

    parts = match["request"].split(" ")
    if len(parts) == 3:
        method, target, protocol = parts
    elif len(parts) == 2:
        (method, target), protocol = parts, ""
    else:
        # Malformed or binary probes such as "\x16\x03..." are kept but flagged.
        method, target, protocol = "-", match["request"], ""
    path = target.split("?", 1)[0].split("#", 1)[0] or "/"

    raw_bytes = match["bytes"]
    rt = match["rt"]
    return LogEntry(
        ip=match["ip"],
        user=match["user"],
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=int(match["status"]),
        bytes_sent=0 if raw_bytes == "-" else int(raw_bytes),
        referer=_none_if_dash(match["referer"]),
        user_agent=_none_if_dash(match["agent"]),
        request_time=float(rt) if rt is not None else None,
    )


def _none_if_dash(value: Optional[str]) -> Optional[str]:
    return None if value in (None, "-") else value
