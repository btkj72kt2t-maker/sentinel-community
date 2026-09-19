from __future__ import annotations

import json
import ipaddress
import secrets
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .db import audit, connect, engagement, now
from .policy import execution_decision


def issue_token(name: str, finding_id: int, ttl_seconds: int = 600) -> dict:
    ttl_seconds = max(60, min(ttl_seconds, 3600))
    token = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        eng = engagement(conn, name)
        if not eng["lab_mode"]:
            raise PermissionError("callback tokens are restricted to isolated lab engagements")
        if not conn.execute("SELECT id FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone():
            raise ValueError("finding does not belong to this lab engagement")
        conn.execute("INSERT INTO callback_tokens(engagement_id,finding_id,token,expires_at,created_at) VALUES(?,?,?,?,?)", (eng["id"], finding_id, token, expires, now()))
        audit(conn, "lab.callback_token_issued", {"finding_id": finding_id, "expires_at": expires}, eng["id"])
    return {"token": token, "callback_url": f"http://127.0.0.1:8765/{token}", "expires_at": expires, "binding": "loopback-only"}


def record_callback(token: str, method: str, path: str, source: str = "127.0.0.1", headers: dict | None = None) -> bool:
    try:
        if not ipaddress.ip_address(source).is_loopback:
            return False
    except ValueError:
        return False
    with connect() as conn:
        row = conn.execute("SELECT * FROM callback_tokens WHERE token=? AND expires_at>=?", (token, now())).fetchone()
        if not row:
            return False
        safe_headers = {str(key): "[PRESENT]" for key in (headers or {}) if str(key).lower() not in {"authorization", "cookie", "set-cookie"}}
        conn.execute("INSERT INTO callback_events(token_id,method,path,source,headers,observed_at) VALUES(?,?,?,?,?,?)", (row["id"], method[:16], path[:2000], source, json.dumps(safe_headers, sort_keys=True), now()))
        audit(conn, "lab.callback_observed", {"finding_id": row["finding_id"], "method": method[:16]}, row["engagement_id"])
    return True


def serve_callbacks(name: str, *, seconds: int = 300, port: int = 8765, approved: bool = False) -> dict:
    seconds = max(1, min(seconds, 600))
    if not 1024 <= port <= 65535:
        raise ValueError("callback port must be between 1024 and 65535")
    with connect() as conn:
        eng = engagement(conn, name)
        decision = execution_decision(eng, active=True, lab_only=True, approved=approved)
        if not decision.allowed:
            raise PermissionError(decision.reason)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            token = self.path.split("?", 1)[0].strip("/").split("/", 1)[0]
            accepted = record_callback(token, "GET", self.path, self.client_address[0], dict(self.headers))
            self.send_response(204 if accepted else 404)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 0.5
    deadline, events_before = time.monotonic() + seconds, _event_count(name)
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    events_after = _event_count(name)
    return {"binding": f"127.0.0.1:{port}", "seconds": seconds, "events_recorded": events_after - events_before}


def _event_count(name: str) -> int:
    with connect() as conn:
        eng = engagement(conn, name)
        return conn.execute("SELECT COUNT(*) FROM callback_events e JOIN callback_tokens t ON t.id=e.token_id WHERE t.engagement_id=?", (eng["id"],)).fetchone()[0]


def list_events(name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, name)
        return [dict(row) for row in conn.execute("SELECT e.*,t.finding_id,t.expires_at FROM callback_events e JOIN callback_tokens t ON t.id=e.token_id WHERE t.engagement_id=? ORDER BY e.id", (eng["id"],))]
