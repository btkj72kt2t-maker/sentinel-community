from __future__ import annotations

import hashlib
import html
import json
import re
from difflib import SequenceMatcher
from pathlib import Path

from .db import audit, connect, engagement, now


SQL_ERRORS = (
    r"sql syntax.*mysql", r"warning.*mysql_", r"postgresql.*error",
    r"unterminated quoted string", r"sqlite(?:3)?\.operationalerror",
    r"ora-\d{4,5}", r"microsoft ole db provider for sql server",
    r"unclosed quotation mark after the character string",
)


def _load(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence must be a JSON object")
    return payload


def _observation(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    body = value.get("body", "")
    if not isinstance(body, str) or len(body) > 2_000_000:
        raise ValueError(f"{name}.body must be text no larger than 2 MB")
    return {"body": body, "status": int(value.get("status", 0)), "elapsed_ms": max(0.0, min(float(value.get("elapsed_ms", 0)), 120_000.0))}


def _summary(observation: dict) -> dict:
    body = observation["body"]
    return {"status": observation["status"], "elapsed_ms": observation["elapsed_ms"], "body_length": len(body), "body_sha256": hashlib.sha256(body.encode()).hexdigest()}


def _store(name: str, finding_id: int, module_id: str, result: dict) -> int:
    with connect() as conn:
        eng = engagement(conn, name)
        finding = conn.execute("SELECT id FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone()
        if not finding:
            raise ValueError("finding does not belong to this engagement")
        timestamp = now()
        cur = conn.execute(
            "INSERT INTO proof_runs(engagement_id,finding_id,module_id,mode,status,request_budget,result,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (eng["id"], finding_id, module_id, "offline", "analyzed", 0, json.dumps(result, sort_keys=True), timestamp, timestamp),
        )
        audit(conn, "proof.offline_analyzed", {"proof_run_id": cur.lastrowid, "finding_id": finding_id, "module_id": module_id, "conclusion": result["conclusion"]}, eng["id"])
        return cur.lastrowid


def analyze_sql_injection_evidence(name: str, finding_id: int, path: Path) -> dict:
    payload = _load(path)
    baseline = _observation(payload.get("baseline"), "baseline")
    variant = _observation(payload.get("variant"), "variant")
    baseline_lower, variant_lower = baseline["body"].lower(), variant["body"].lower()
    introduced = [pattern for pattern in SQL_ERRORS if re.search(pattern, variant_lower) and not re.search(pattern, baseline_lower)]
    similarity = SequenceMatcher(None, baseline["body"], variant["body"]).ratio()
    timing_delta = variant["elapsed_ms"] - baseline["elapsed_ms"]
    signals = {"introduced_database_error_signatures": introduced, "status_changed": baseline["status"] != variant["status"], "body_similarity": round(similarity, 4), "timing_delta_ms": round(timing_delta, 2), "timing_anomaly": timing_delta >= 3000}
    strong = bool(introduced)
    suspicious = strong or signals["status_changed"] or similarity < 0.75 or signals["timing_anomaly"]
    result = {"conclusion": "strong-sql-injection-signal" if strong else ("differential-requires-review" if suspicious else "no-material-differential"), "confidence": "medium" if strong else "low", "baseline": _summary(baseline), "variant": _summary(variant), "signals": signals, "limitations": "Offline differential analysis does not prove exploitability, database access, or data extraction."}
    result["proof_run_id"] = _store(name, finding_id, "sql-injection-evidence", result)
    return result


def analyze_xss_evidence(name: str, finding_id: int, path: Path) -> dict:
    payload = _load(path)
    marker, response = payload.get("marker"), payload.get("response")
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", marker):
        raise ValueError("marker must be 8-128 inert characters")
    if not isinstance(response, dict):
        raise ValueError("response must be an object")
    body = response.get("body", "")
    if not isinstance(body, str) or len(body) > 2_000_000:
        raise ValueError("response.body must be text no larger than 2 MB")
    content_type = str(response.get("content_type", "")).lower()[:200]
    exact = marker in body
    escaped_marker = html.escape(marker, quote=True)
    escaped = escaped_marker in body and escaped_marker != marker
    script_context = bool(re.search(r"<script\b[^>]*>[^<]*" + re.escape(marker), body, re.IGNORECASE)) if exact else False
    attribute_context = bool(re.search(r"<[^>]+=[\"'][^\"']*" + re.escape(marker), body, re.IGNORECASE)) if exact else False
    result = {"conclusion": "inert-marker-reflected" if exact else ("marker-encoded" if escaped else "marker-not-reflected"), "confidence": "medium" if exact else "low", "response": {"content_type": content_type, "body_length": len(body), "body_sha256": hashlib.sha256(body.encode()).hexdigest()}, "signals": {"exact_reflection": exact, "encoded_reflection": escaped, "script_context": script_context, "attribute_context": attribute_context}, "limitations": "Inert reflection is not proof of executable XSS. Browser-context validation remains a controlled lab/manual step."}
    result["proof_run_id"] = _store(name, finding_id, "xss-reflection-evidence", result)
    return result
