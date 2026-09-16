from __future__ import annotations

import json
import platform
import sqlite3
import statistics
import tempfile
import time
from pathlib import Path


def _measure(fn, iterations: int) -> dict:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(samples)
    return {"iterations": iterations, "median_ms": round(statistics.median(samples), 4), "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 4), "min_ms": round(min(samples), 4), "max_ms": round(max(samples), 4)}


def run_benchmarks(iterations: int = 100) -> dict:
    iterations = max(10, min(iterations, 10000))
    payload = {"target": "example.test", "findings": [{"severity": "low", "title": "fixture"}] * 25}
    json_result = _measure(lambda: json.loads(json.dumps(payload)), iterations)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "bench.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE samples(id INTEGER PRIMARY KEY,value TEXT)")
        counter = iter(range(iterations))
        db_result = _measure(lambda: conn.execute("INSERT INTO samples(value) VALUES(?)", (f"sample-{next(counter)}",)), iterations)
        conn.commit()
        conn.close()
    return {"environment": {"python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor() or "unknown"}, "json_roundtrip": json_result, "sqlite_insert": db_result, "note": "Local microbenchmark; not a network-throughput claim"}

