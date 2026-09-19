from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path

from .db import audit, connect, engagement, now


SENSITIVE = re.compile(r"(?i)(authorization|cookie|set-cookie|api[-_]?key|token|secret|password)")


def _sanitize_headers(headers: dict) -> dict:
    return {str(key): "[REDACTED]" if SENSITIVE.search(str(key)) else str(value)[:2000] for key, value in headers.items()}


def _response(value: dict) -> dict:
    body = str(value.get("body") or "")
    return {"status": int(value.get("status") or 0), "headers": _sanitize_headers(value.get("headers") or {}), "body_length": len(body.encode()), "body_sha256": hashlib.sha256(body.encode()).hexdigest(), "body": body}


def analyze_differential(name: str, finding_id: int, path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document.get("baseline"), dict) or not isinstance(document.get("variant"), dict):
        raise ValueError("differential input requires baseline and variant responses")
    baseline, variant = _response(document["baseline"]), _response(document["variant"])
    similarity = round(difflib.SequenceMatcher(None, baseline.pop("body"), variant.pop("body")).ratio(), 4)
    result = {"baseline": baseline, "variant": variant, "delta": {"status_changed": baseline["status"] != variant["status"], "length_delta": variant["body_length"] - baseline["body_length"], "body_similarity": similarity, "header_names_added": sorted(set(variant["headers"]) - set(baseline["headers"])), "header_names_removed": sorted(set(baseline["headers"]) - set(variant["headers"]))}, "interpretation": "review-required"}
    if baseline["status"] in {401, 403} and variant["status"] in range(200, 300):
        result["interpretation"] = "possible-authorization-bypass"
    elif similarity < 0.5 or result["delta"]["status_changed"]:
        result["interpretation"] = "material-response-difference"
    with connect() as conn:
        eng = engagement(conn, name)
        finding = conn.execute("SELECT id FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone()
        if not finding:
            raise ValueError("finding does not belong to this engagement")
        cur = conn.execute("INSERT INTO proof_runs(engagement_id,finding_id,module_id,mode,status,result,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], finding_id, "http-differential", "offline", "completed", json.dumps(result, sort_keys=True), now(), now()))
        audit(conn, "proof.differential_analyzed", {"proof_run_id": cur.lastrowid, "finding_id": finding_id, "interpretation": result["interpretation"]}, eng["id"])
        result["proof_run_id"] = cur.lastrowid
    return result


def analyze_authorization_matrix(name: str, finding_id: int, path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    observations = document.get("observations")
    if not isinstance(observations, list):
        raise ValueError("authorization matrix requires an observations array")
    violations = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        if not isinstance(item.get("expected_allowed"), bool) or not isinstance(item.get("observed_allowed"), bool):
            raise ValueError("authorization matrix decisions must be JSON booleans")
        expected = bool(item.get("expected_allowed"))
        observed = bool(item.get("observed_allowed"))
        if expected != observed:
            violations.append({"role": str(item.get("role")), "resource": str(item.get("resource")), "action": str(item.get("action")), "expected_allowed": expected, "observed_allowed": observed})
    result = {"observations": len(observations), "violations": violations, "status": "violations-found" if violations else "policy-consistent"}
    with connect() as conn:
        eng = engagement(conn, name)
        if not conn.execute("SELECT id FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone():
            raise ValueError("finding does not belong to this engagement")
        cur = conn.execute("INSERT INTO proof_runs(engagement_id,finding_id,module_id,mode,status,result,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], finding_id, "authorization-matrix", "offline", "completed", json.dumps(result, sort_keys=True), now(), now()))
        audit(conn, "proof.authorization_matrix_analyzed", {"proof_run_id": cur.lastrowid, "finding_id": finding_id, "violations": len(violations)}, eng["id"])
        result["proof_run_id"] = cur.lastrowid
    return result
