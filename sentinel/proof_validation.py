from __future__ import annotations

import hashlib
from pathlib import Path

from .db import audit, connect, engagement, now


OUTCOMES = {"confirmed", "not-reproduced", "inconclusive"}


def record_proof(name: str, finding_id: int, evidence: Path, outcome: str, *, rollback_verified: bool = False, notes: str = "") -> dict:
    if outcome not in OUTCOMES:
        raise ValueError("unsupported proof outcome")
    if not evidence.is_file():
        raise ValueError("proof evidence must be a file")
    if outcome == "confirmed" and not rollback_verified:
        raise PermissionError("confirmed proof requires verified rollback or cleanup")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    with connect() as conn:
        eng = engagement(conn, name)
        if not eng["lab_mode"]:
            raise PermissionError("proof recording is restricted to isolated lab engagements")
        finding = conn.execute("SELECT * FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone()
        if not finding:
            raise ValueError("finding does not belong to this lab engagement")
        cur = conn.execute("INSERT INTO validation_proofs(engagement_id,finding_id,outcome,evidence_path,evidence_sha256,rollback_verified,notes,created_at) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], finding_id, outcome, str(evidence.resolve()), digest, int(rollback_verified), notes[:4000], now()))
        if outcome == "confirmed":
            conn.execute("UPDATE findings SET status='confirmed' WHERE id=?", (finding_id,))
        audit(conn, "lab.proof_recorded", {"proof_id": cur.lastrowid, "finding_id": finding_id, "outcome": outcome, "evidence_sha256": digest, "rollback_verified": rollback_verified}, eng["id"])
    return {"proof_id": cur.lastrowid, "finding_id": finding_id, "outcome": outcome, "evidence_sha256": digest, "rollback_verified": rollback_verified}


def list_proofs(name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, name)
        return [dict(row) for row in conn.execute("SELECT * FROM validation_proofs WHERE engagement_id=? ORDER BY id", (eng["id"],))]
