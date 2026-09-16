from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from .db import audit, connect, engagement, now
from .scope import target_allowed


def _headers(items) -> dict[str, str]:
    return {str(i.get("name", "")).lower(): str(i.get("value", "")) for i in items or []}


def _observation(method: str, url: str, status: int | None, severity: str, title: str, details: dict) -> dict:
    fingerprint = hashlib.sha256(f"{method}\0{url}\0{title}".encode()).hexdigest()
    return {"method": method, "url": url, "status": status, "severity": severity, "title": title, "details": details, "fingerprint": fingerprint}


def analyze_har(engagement_name: str, har_path: Path) -> dict:
    payload = json.loads(har_path.read_text(encoding="utf-8"))
    entries = payload.get("log", {}).get("entries", [])
    observations = []
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        for entry in entries:
            request, response = entry.get("request", {}), entry.get("response", {})
            method, url = request.get("method", "GET"), request.get("url", "")
            host = (urlparse(url).hostname or "").lower()
            if not host or not target_allowed(host, scopes):
                continue
            status = response.get("status")
            req_headers, res_headers = _headers(request.get("headers")), _headers(response.get("headers"))
            if url.startswith("http://"):
                observations.append(_observation(method, url, status, "medium", "Cleartext HTTP transport", {"host": host}))
            required = {"content-security-policy", "strict-transport-security", "x-content-type-options"}
            missing = sorted(required - set(res_headers))
            if missing:
                observations.append(_observation(method, url, status, "low", "Missing defensive response headers", {"missing": missing}))
            cookies = [v for k, v in res_headers.items() if k == "set-cookie"]
            for cookie in cookies:
                flags = cookie.lower()
                absent = [name for name in ("secure", "httponly", "samesite") if name not in flags]
                if absent:
                    observations.append(_observation(method, url, status, "medium", "Cookie missing security attributes", {"missing": absent, "cookie_name": cookie.split("=", 1)[0]}))
            if "authorization" in req_headers:
                observations.append(_observation(method, url, status, "info", "Authenticated request observed", {"scheme": req_headers["authorization"].split(" ", 1)[0], "value": "[REDACTED]"}))
        for item in observations:
            conn.execute(
                "INSERT INTO proxy_observations(engagement_id,target,method,url,status,severity,title,details,fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(engagement_id,fingerprint) DO UPDATE SET status=excluded.status,details=excluded.details",
                (eng["id"], urlparse(item["url"]).hostname, item["method"], item["url"], item["status"], item["severity"], item["title"], json.dumps(item["details"], sort_keys=True), item["fingerprint"], now()),
            )
        audit(conn, "proxy.har_analyzed", {"file": har_path.name, "entries": len(entries), "observations": len(observations)}, eng["id"])
    return {"entries": len(entries), "in_scope_observations": len(observations), "observations": observations}

