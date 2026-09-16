from __future__ import annotations

import hashlib
from pathlib import Path

from .db import audit, connect, engagement, now


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_health(engagement_name: str, repair: bool = False) -> dict:
    checks = []
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        checks.append({"check": "database_integrity", "ok": integrity == "ok", "detail": integrity})
        stale = conn.execute(
            "SELECT id FROM jobs WHERE engagement_id=? AND status='running' AND started_at < datetime('now','-6 hours')",
            (eng["id"],),
        ).fetchall()
        checks.append({"check": "stale_jobs", "ok": not stale, "count": len(stale)})
        if repair and stale:
            conn.executemany("UPDATE jobs SET status='queued',message='Recovered by health engine' WHERE id=?", [(r["id"],) for r in stale])
        missing, changed, verified = [], [], 0
        for row in conn.execute("SELECT * FROM evidence WHERE engagement_id=?", (eng["id"],)):
            path = Path(row["stored_path"])
            if not path.is_file():
                missing.append(row["id"])
                continue
            actual = _sha256(path)
            if actual != row["sha256"]:
                changed.append(row["id"])
                continue
            verified += 1
            conn.execute("UPDATE evidence SET verified_at=? WHERE id=?", (now(), row["id"]))
        checks.append({"check": "evidence_integrity", "ok": not missing and not changed, "verified": verified, "missing": missing, "changed": changed})
        audit(conn, "health.checked", {"repair": repair, "checks": checks}, eng["id"])
    return {"engagement": engagement_name, "healthy": all(c["ok"] for c in checks), "checks": checks, "repaired_stale_jobs": len(stale) if repair else 0}


def evidence_inventory(engagement_name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        rows = conn.execute(
            "SELECT id,original_name,stored_path,sha256,size,classification,category,created_at,verified_at FROM evidence WHERE engagement_id=? ORDER BY id",
            (eng["id"],),
        ).fetchall()
        return [dict(r) for r in rows]

