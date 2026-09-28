from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .db import audit, connect, engagement, now
from .scope import target_allowed


SENSITIVE_QUERY_NAMES = {"access_token", "api_key", "apikey", "auth", "jwt", "password", "secret", "session", "token"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _header_values(items: object, name: str) -> list[str]:
    if not isinstance(items, list):
        return []
    wanted = name.lower()
    return [str(item.get("value", "")) for item in items if isinstance(item, dict) and str(item.get("name", "")).lower() == wanted]


def analyze_auth_har(engagement_name: str, har_path: Path) -> dict:
    """Analyze authentication/session metadata without retaining credentials or bodies."""
    payload = json.loads(har_path.read_text(encoding="utf-8"))
    entries = payload.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log entries must be an array")
    observations: list[dict] = []
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        in_scope = 0
        authenticated = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            request, response = entry.get("request") or {}, entry.get("response") or {}
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue
            url = str(request.get("url") or "")
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if not host or not target_allowed(host, scopes):
                continue
            in_scope += 1
            method = str(request.get("method") or "GET").upper()
            req_headers, res_headers = request.get("headers"), response.get("headers")
            has_authorization = bool(_header_values(req_headers, "authorization"))
            has_cookie = bool(_header_values(req_headers, "cookie"))
            if has_authorization or has_cookie:
                authenticated += 1
            query_names = sorted({name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)} & SENSITIVE_QUERY_NAMES)
            if query_names:
                observations.append({"severity": "high", "title": "Credential-like value transported in URL query", "host": host, "method": method, "path": parsed.path, "details": {"parameter_names": query_names}})
            for cookie in _header_values(res_headers, "set-cookie"):
                flags = cookie.lower()
                name = cookie.split("=", 1)[0][:128]
                missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in flags]
                if missing:
                    observations.append({"severity": "medium", "title": "Session cookie missing defensive attributes", "host": host, "method": method, "path": parsed.path, "details": {"cookie_name": name, "missing": missing}})
            allow_origin = _header_values(res_headers, "access-control-allow-origin")
            allow_credentials = [value.lower() for value in _header_values(res_headers, "access-control-allow-credentials")]
            if "*" in allow_origin and "true" in allow_credentials:
                observations.append({"severity": "high", "title": "Credentialed CORS response uses wildcard origin", "host": host, "method": method, "path": parsed.path, "details": {}})
            if (has_authorization or has_cookie) and int(response.get("status") or 0) in range(200, 300):
                cache_control = ",".join(_header_values(res_headers, "cache-control")).lower()
                if not any(token in cache_control for token in ("no-store", "private")):
                    observations.append({"severity": "low", "title": "Authenticated response lacks an explicit private/no-store cache policy", "host": host, "method": method, "path": parsed.path, "details": {}})
            if method in UNSAFE_METHODS and has_cookie and not has_authorization:
                names = {str(item.get("name", "")).lower() for item in (req_headers or []) if isinstance(item, dict)}
                csrf_evidence = any(name in names for name in ("x-csrf-token", "x-xsrf-token", "csrf-token"))
                if not csrf_evidence:
                    observations.append({"severity": "info", "title": "Cookie-authenticated state-changing request needs CSRF review", "host": host, "method": method, "path": parsed.path, "details": {"claim": "review-required"}})
        for item in observations:
            fingerprint = hashlib.sha256(f"{item['title']}\0{item['host']}\0{item['method']}\0{item['path']}".encode()).hexdigest()
            details = json.dumps(item["details"], sort_keys=True)
            existing = conn.execute("SELECT id FROM findings WHERE engagement_id=? AND fingerprint=?", (eng["id"], fingerprint)).fetchone()
            if existing:
                conn.execute("UPDATE findings SET occurrences=occurrences+1,details=?,severity=? WHERE id=?", (details, item["severity"], existing["id"]))
            else:
                conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at,fingerprint) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], item["host"], "auth-har-offline", item["severity"], item["title"], details, now(), fingerprint))
        audit(conn, "auth.har_analyzed", {"file": har_path.name, "entries": len(entries), "in_scope": in_scope, "authenticated": authenticated, "observations": len(observations)}, eng["id"])
    return {"entries": len(entries), "in_scope_entries": in_scope, "authenticated_entries": authenticated, "observations": observations, "credentials_stored": False, "mode": "offline"}
