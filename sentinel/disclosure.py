from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .config import reports_dir
from .db import audit, connect, engagement, now
from .taxonomy import recommendations


SENSITIVE = re.compile(r"(?i)(authorization|cookie|token|secret|password|api[-_]?key)")


def _redact(value):
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if SENSITIVE.search(str(key)) else _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 10000:
        return value[:10000] + "…[TRUNCATED]"
    return value


def build_disclosure(name: str, finding_id: int) -> dict:
    with connect() as conn:
        eng = engagement(conn, name)
        finding = conn.execute("SELECT * FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone()
        if not finding:
            raise ValueError("finding does not belong to this engagement")
        finding_dict = dict(finding)
        try:
            finding_dict["details"] = _redact(json.loads(finding_dict["details"] or "{}"))
        except json.JSONDecodeError:
            finding_dict["details"] = "[UNPARSEABLE DETAILS REDACTED]"
        proof_runs = [dict(row) for row in conn.execute("SELECT * FROM proof_runs WHERE finding_id=? ORDER BY id", (finding_id,))]
        proofs = [dict(row) for row in conn.execute("SELECT * FROM validation_proofs WHERE finding_id=? ORDER BY id", (finding_id,))]
        callbacks = [dict(row) for row in conn.execute("SELECT e.method,e.path,e.source,e.headers,e.observed_at FROM callback_events e JOIN callback_tokens t ON t.id=e.token_id WHERE t.finding_id=? ORDER BY e.id", (finding_id,))]
        cves = [dict(row) for row in conn.execute("SELECT v.* FROM vulnerability_intelligence v JOIN finding_vulnerabilities fv ON fv.cve=v.cve WHERE fv.finding_id=?", (finding_id,))]
        package = {"schema": "sentinel-disclosure-1.0", "generated_at": now(), "engagement": {"name": eng["name"]}, "finding": finding_dict, "vulnerability_intelligence": _redact(cves), "proof_runs": _redact(proof_runs), "lab_proofs": _redact(proofs), "callback_events": _redact(callbacks), "remediation": recommendations([finding_dict]), "assurance": "Sanitized evidence package; verify scope, impact, and redaction before external disclosure."}
        audit(conn, "disclosure.generated", {"finding_id": finding_id}, eng["id"])
    directory = reports_dir() / "disclosures"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}-finding-{finding_id}.json"
    encoded = json.dumps(package, indent=2, sort_keys=True).encode()
    path.write_bytes(encoded)
    return {"path": str(path), "sha256": hashlib.sha256(encoded).hexdigest(), "finding_id": finding_id}
