from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .db import audit, connect, now


def add_known_signature(fingerprint: str, reference: str, source: str = "manual") -> None:
    if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint.lower()):
        raise ValueError("fingerprint must be a SHA-256 hex digest")
    with connect() as conn:
        conn.execute("INSERT INTO known_signatures(fingerprint,reference,source,created_at) VALUES(?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET reference=excluded.reference,source=excluded.source", (fingerprint.lower(), reference, source, now()))
        audit(conn, "research.known_signature_added", {"fingerprint": fingerprint.lower(), "reference": reference, "source": source})


def record_reproduction(crash_id: int, input_path: Path, outcome: str, sanitizer: str | None = None, environment: dict | None = None) -> int:
    if outcome not in {"reproduced", "not_reproduced", "timeout"}:
        raise ValueError("unsupported reproduction outcome")
    digest = hashlib.sha256(input_path.read_bytes()).hexdigest()
    with connect() as conn:
        crash = conn.execute("SELECT c.*,r.engagement_id FROM crashes c JOIN research_campaigns r ON r.id=c.campaign_id WHERE c.id=?", (crash_id,)).fetchone()
        if not crash:
            raise ValueError("unknown crash")
        cur = conn.execute("INSERT INTO reproductions(crash_id,input_sha256,outcome,sanitizer,environment,created_at) VALUES(?,?,?,?,?,?)", (crash_id, digest, outcome, sanitizer, json.dumps(environment or {}, sort_keys=True), now()))
        audit(conn, "research.reproduction_recorded", {"crash_id": crash_id, "outcome": outcome, "input_sha256": digest}, crash["engagement_id"])
        return cur.lastrowid


def score_candidate(crash_id: int) -> dict:
    with connect() as conn:
        crash = conn.execute("SELECT c.*,r.engagement_id FROM crashes c JOIN research_campaigns r ON r.id=c.campaign_id WHERE c.id=?", (crash_id,)).fetchone()
        if not crash:
            raise ValueError("unknown crash")
        known = conn.execute("SELECT * FROM known_signatures WHERE fingerprint=?", (crash["fingerprint"],)).fetchone()
        rows = conn.execute("SELECT * FROM reproductions WHERE crash_id=?", (crash_id,)).fetchall()
        reproduced = sum(1 for row in rows if row["outcome"] == "reproduced")
        sanitizer_backed = any(row["sanitizer"] for row in rows if row["outcome"] == "reproduced")
        crash_strength = 25 if crash["crash_type"] != "unknown" else 5
        reproducibility = min(40, reproduced * 20)
        sanitizer_score = 20 if sanitizer_backed else 0
        novelty_score = 0 if known else 15
        score = crash_strength + reproducibility + sanitizer_score + novelty_score
        classification = "known" if known else "zero-day-candidate" if score >= 80 and reproduced >= 2 else "needs-more-evidence"
        result = {"crash_id": crash_id, "score": score, "classification": classification, "known_reference": dict(known) if known else None, "evidence": {"crash_type": crash["crash_type"], "reproductions": reproduced, "sanitizer_backed": sanitizer_backed, "absent_from_local_signatures": not bool(known)}, "warning": "Candidate status is not proof of public novelty; vendor and external-database review are required"}
        audit(conn, "research.candidate_scored", result, crash["engagement_id"])
        return result

