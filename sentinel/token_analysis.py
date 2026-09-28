from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from pathlib import Path

from .db import audit, connect, engagement, now


def _decode(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(segment + padding))
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise ValueError("token contains invalid base64url JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("token header and payload must be JSON objects")
    return value


def analyze_jwt(engagement_name: str, token_path: Path, at_time: int | None = None) -> dict:
    raw = token_path.read_text(encoding="utf-8").strip()
    if len(raw) > 65536 or len(raw.split(".")) != 3:
        raise ValueError("expected one compact three-segment JWT no larger than 64 KiB")
    header_segment, payload_segment, signature_segment = raw.split(".")
    header, payload = _decode(header_segment), _decode(payload_segment)
    current = int(time.time() if at_time is None else at_time)
    algorithm = str(header.get("alg") or "")
    findings = []
    if not algorithm or algorithm.lower() == "none" or not signature_segment:
        findings.append({"severity": "critical", "title": "JWT has no cryptographic signature algorithm", "details": {"algorithm": algorithm or "missing"}})
    expires = payload.get("exp")
    issued = payload.get("iat")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        findings.append({"severity": "medium", "title": "JWT has no numeric expiration claim", "details": {}})
    elif expires < current:
        findings.append({"severity": "info", "title": "JWT is expired at analysis time", "details": {"seconds_expired": int(current - expires)}})
    if not isinstance(expires, bool) and not isinstance(issued, bool) and isinstance(expires, (int, float)) and isinstance(issued, (int, float)) and expires - issued > 86400:
        findings.append({"severity": "low", "title": "JWT lifetime exceeds 24 hours", "details": {"lifetime_seconds": int(expires - issued)}})
    missing_context = [claim for claim in ("iss", "aud") if claim not in payload]
    if missing_context:
        findings.append({"severity": "low", "title": "JWT lacks validation-context claims", "details": {"missing": missing_context}})
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        for item in findings:
            finding_fingerprint = hashlib.sha256(f"jwt\0{fingerprint}\0{item['title']}".encode()).hexdigest()
            details = json.dumps(item["details"], sort_keys=True)
            existing = conn.execute("SELECT id FROM findings WHERE engagement_id=? AND fingerprint=?", (eng["id"], finding_fingerprint)).fetchone()
            if existing:
                conn.execute("UPDATE findings SET occurrences=occurrences+1,details=?,severity=? WHERE id=?", (details, item["severity"], existing["id"]))
            else:
                conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at,fingerprint) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], "offline:jwt", "jwt-offline", item["severity"], item["title"], details, now(), finding_fingerprint))
        audit(conn, "auth.jwt_analyzed", {"file": token_path.name, "token_sha256": fingerprint, "algorithm": algorithm or "missing", "findings": len(findings)}, eng["id"])
    return {"token_sha256": fingerprint, "algorithm": algorithm or "missing", "claims_present": sorted(str(key) for key in payload), "findings": findings, "signature_verified": False, "token_stored": False, "mode": "offline"}
