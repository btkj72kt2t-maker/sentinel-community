from __future__ import annotations

import json
from pathlib import Path

from .db import audit, connect, now

REQUIRED = {"executions", "edges", "paths", "crashes", "hangs"}


def import_coverage(campaign_id: int, telemetry_path: Path) -> dict:
    payload = json.loads(telemetry_path.read_text(encoding="utf-8"))
    missing = REQUIRED - set(payload)
    if missing:
        raise ValueError(f"missing telemetry fields: {', '.join(sorted(missing))}")
    metrics = {key: max(0, int(payload[key])) for key in REQUIRED}
    with connect() as conn:
        campaign = conn.execute("SELECT * FROM research_campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not campaign:
            raise ValueError("unknown campaign")
        previous = conn.execute("SELECT edges,paths,executions FROM coverage_samples WHERE campaign_id=? ORDER BY id DESC LIMIT 1", (campaign_id,)).fetchone()
        conn.execute("INSERT INTO coverage_samples(campaign_id,executions,edges,paths,crashes,hangs,sampled_at) VALUES(?,?,?,?,?,?,?)", (campaign_id, metrics["executions"], metrics["edges"], metrics["paths"], metrics["crashes"], metrics["hangs"], now()))
        delta = {"edges": metrics["edges"] - (previous["edges"] if previous else 0), "paths": metrics["paths"] - (previous["paths"] if previous else 0), "executions": metrics["executions"] - (previous["executions"] if previous else 0)}
        audit(conn, "research.coverage_imported", {"campaign_id": campaign_id, "metrics": metrics, "delta": delta}, campaign["engagement_id"])
    return {"campaign_id": campaign_id, "metrics": metrics, "delta": delta}


def coverage_trend(campaign_id: int) -> dict:
    with connect() as conn:
        samples = [dict(r) for r in conn.execute("SELECT * FROM coverage_samples WHERE campaign_id=? ORDER BY id", (campaign_id,))]
    return {"campaign_id": campaign_id, "samples": samples, "latest": samples[-1] if samples else None}

