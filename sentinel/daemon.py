from __future__ import annotations

import json
import time
from pathlib import Path

from .config import data_dir
from .db import audit, connect, engagement, now
from .health import check_health
from .jobs import run_next


def daemon_status(engagement_name: str) -> dict:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        counts = {row["status"]: row["count"] for row in conn.execute("SELECT status,COUNT(*) count FROM jobs WHERE engagement_id=? GROUP BY status", (eng["id"],))}
    stop_file = data_dir() / f"stop-{engagement_name}"
    heartbeat = data_dir() / f"heartbeat-{engagement_name}.json"
    heartbeat_data = json.loads(heartbeat.read_text()) if heartbeat.exists() else None
    return {"engagement": engagement_name, "kill_switch": bool(eng["kill_switch"]), "stop_requested": stop_file.exists(), "jobs": counts, "heartbeat": heartbeat_data}


def request_stop(engagement_name: str) -> Path:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        audit(conn, "daemon.stop_requested", {}, eng["id"])
    path = data_dir() / f"stop-{engagement_name}"
    path.write_text(now(), encoding="utf-8")
    return path


def run_daemon(engagement_name: str, poll_seconds: int = 15, max_jobs: int = 100, max_runtime: int = 86400) -> dict:
    poll_seconds = max(1, min(poll_seconds, 3600))
    max_jobs = max(1, min(max_jobs, 10000))
    max_runtime = max(1, min(max_runtime, 7 * 86400))
    stop_file = data_dir() / f"stop-{engagement_name}"
    heartbeat = data_dir() / f"heartbeat-{engagement_name}.json"
    if stop_file.exists():
        stop_file.unlink()
    started = time.monotonic()
    processed, cycles = 0, 0
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        audit(conn, "daemon.started", {"poll_seconds": poll_seconds, "max_jobs": max_jobs, "max_runtime": max_runtime}, eng["id"])
    reason = "runtime_limit"
    while time.monotonic() - started < max_runtime and processed < max_jobs:
        cycles += 1
        with connect() as conn:
            eng = engagement(conn, engagement_name)
            if eng["kill_switch"]:
                reason = "kill_switch"
                break
        if stop_file.exists():
            reason = "stop_requested"
            break
        result = run_next(engagement_name)
        if result:
            processed += 1
        if cycles == 1 or cycles % 20 == 0:
            check_health(engagement_name, repair=True)
        heartbeat.write_text(json.dumps({"at": now(), "processed": processed, "cycles": cycles, "last_job": result}, indent=2), encoding="utf-8")
        if not result:
            time.sleep(poll_seconds)
    if processed >= max_jobs:
        reason = "job_limit"
    summary = {"engagement": engagement_name, "processed": processed, "cycles": cycles, "reason": reason, "finished_at": now()}
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        audit(conn, "daemon.stopped", summary, eng["id"])
    heartbeat.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary

