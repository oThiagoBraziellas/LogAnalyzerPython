"""Writes a deterministic sample log: python3 samples/make_sample.py > samples/access.sample"""

import random
from datetime import datetime, timedelta, timezone

rng = random.Random(7)
paths = [("/", 40), ("/api/items", 30), ("/api/items/42", 12), ("/login", 8), ("/static/app.js", 6), ("/admin", 2), ("/health", 2)]
statuses = [(200, 90), (301, 3), (304, 3), (404, 2), (500, 2)]
ips = [f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 60)}" for _ in range(25)]
start = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

def pick(options):
    return rng.choices([o for o, _ in options], [w for _, w in options])[0]

for i in range(2000):
    ts = (start + timedelta(seconds=i * 2)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    path = pick(paths)
    status = pick(statuses)
    base = 0.45 if path.startswith("/api") else 0.02
    latency = rng.lognormvariate(0, 0.6) * base
    print(f'{rng.choice(ips)} - - [{ts}] "GET {path}?q={i % 7} HTTP/1.1" {status} {rng.randint(120, 9000)} "-" "Mozilla/5.0" {latency:.3f}')
