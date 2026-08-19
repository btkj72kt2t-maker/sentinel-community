from __future__ import annotations

import json

from .db import audit, connect, engagement, now
from .workflow import run_workflow


def enqueue_workflow(engagement_name: str, workflow_id: int, approve_active: bool = False) -> int:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        flow = conn.execute("SELECT * FROM workflows WHERE id=? AND engagement_id=?", (workflow_id, eng["id"])).fetchone()
        if not flow:
            raise ValueError("workflow does not belong to this engagement")
        payload = {"workflow_id": workflow_id, "approve_active": approve_active}
        cur = conn.execute("INSERT INTO jobs(engagement_id,kind,payload,status,created_at) VALUES(?,'workflow',?,'queued',?)", (eng["id"], json.dumps(payload, sort_keys=True), now()))
        audit(conn, "job.queued", {"job_id": cur.lastrowid, **payload}, eng["id"])
        return cur.lastrowid


def list_jobs(engagement_name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        return [dict(r) for r in conn.execute("SELECT * FROM jobs WHERE engagement_id=? ORDER BY id DESC", (eng["id"],))]


def run_next(engagement_name: str) -> dict | None:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        if eng["kill_switch"]:
            raise PermissionError("engagement kill switch is active")
        job = conn.execute("SELECT * FROM jobs WHERE engagement_id=? AND status='queued' ORDER BY id LIMIT 1", (eng["id"],)).fetchone()
        if not job:
            return None
        conn.execute("UPDATE jobs SET status='running',attempts=attempts+1,started_at=? WHERE id=?", (now(), job["id"]))
    payload = json.loads(job["payload"])
    try:
        result = run_workflow(payload["workflow_id"], approve_active=bool(payload.get("approve_active")))
        status, message = "completed", json.dumps(result, sort_keys=True)[:4000]
    except Exception as exc:
        status, message = "failed", str(exc)[:4000]
    with connect() as conn:
        conn.execute("UPDATE jobs SET status=?,message=?,finished_at=? WHERE id=?", (status, message, now(), job["id"]))
        audit(conn, "job.finished", {"job_id": job["id"], "status": status}, job["engagement_id"])
    return {"job_id": job["id"], "status": status, "message": message}

