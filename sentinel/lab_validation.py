from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .db import audit, connect, engagement
from .policy import execution_decision


def _loopback_host(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return True
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(address).is_loopback for address in addresses)


def validate_marker(engagement_name: str, target_url: str, approve_active: bool = False) -> dict:
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP(S) URL")
    if not _loopback_host(parsed.hostname):
        raise PermissionError("automated marker validation is restricted to loopback lab targets")
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        decision = execution_decision(eng, active=True, lab_only=True, approved=approve_active)
        if not decision.allowed:
            raise PermissionError(decision.reason)
    marker = f"sentinel-{uuid.uuid4().hex}"
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("sentinel_marker", marker))
    url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    request = urllib.request.Request(url, headers={"User-Agent": "Sentinel-Community-Lab-Validator/1.0", "X-Sentinel-Marker": marker})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(1024 * 1024).decode("utf-8", errors="replace")
            result = {"status": response.status, "reflected": marker in body, "marker_sha256": __import__("hashlib").sha256(marker.encode()).hexdigest(), "body_bytes_examined": len(body.encode())}
    except urllib.error.HTTPError as exc:
        body = exc.read(1024 * 1024).decode("utf-8", errors="replace")
        result = {"status": exc.code, "reflected": marker in body, "marker_sha256": __import__("hashlib").sha256(marker.encode()).hexdigest(), "body_bytes_examined": len(body.encode())}
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        audit(conn, "lab.marker_validated", {"target": f"{parsed.scheme}://{parsed.netloc}{parsed.path}", **result}, eng["id"])
    return result

