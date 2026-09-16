from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .db import audit, connect, engagement, now
from .jobs import enqueue_workflow
from .workflow import PROFILES, create_workflow
from .scope import normalize_target, target_allowed


def add_schedule(name: str, target: str, profile: str, interval_seconds: int, approve_active: bool = False) -> int:
    if profile not in PROFILES:
        raise ValueError("unknown workflow profile")
    interval_seconds = max(300, min(interval_seconds, 2_592_000))
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).isoformat()
    with connect() as conn:
        eng = engagement(conn, name)
        host = normalize_target(target)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        if not target_allowed(host, scopes):
            audit(conn, "scope.denied", {"target": host, "schedule": profile}, eng["id"])
            raise PermissionError(f"{host} is outside engagement scope")
        cur = conn.execute("INSERT INTO schedules(engagement_id,target,profile,interval_seconds,approve_active,next_run_at,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(engagement_id,target,profile) DO UPDATE SET interval_seconds=excluded.interval_seconds,approve_active=excluded.approve_active,enabled=1,next_run_at=excluded.next_run_at RETURNING id", (eng["id"], target, profile, interval_seconds, int(approve_active), next_run, now()))
        schedule_id = cur.fetchone()[0]
        audit(conn, "schedule.saved", {"schedule_id": schedule_id, "target": target, "profile": profile, "interval_seconds": interval_seconds}, eng["id"])
    return schedule_id


def enqueue_due(name: str) -> dict:
    timestamp = now()
    with connect() as conn:
        eng = engagement(conn, name)
        if eng["kill_switch"]:
            raise PermissionError("engagement kill switch is active")
        due = [dict(r) for r in conn.execute("SELECT * FROM schedules WHERE engagement_id=? AND enabled=1 AND next_run_at<=?", (eng["id"], timestamp))]
    queued = []
    for item in due:
        workflow_id = create_workflow(name, item["target"], item["profile"])
        job_id = enqueue_workflow(name, workflow_id, bool(item["approve_active"]))
        next_run = (datetime.now(timezone.utc) + timedelta(seconds=item["interval_seconds"])).isoformat()
        with connect() as conn:
            conn.execute("UPDATE schedules SET last_run_at=?,next_run_at=? WHERE id=?", (timestamp, next_run, item["id"]))
        queued.append({"schedule_id": item["id"], "workflow_id": workflow_id, "job_id": job_id})
    return {"engagement": name, "queued": queued}


def list_schedules(name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, name)
        return [dict(r) for r in conn.execute("SELECT * FROM schedules WHERE engagement_id=? ORDER BY id", (eng["id"],))]
