from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from .db import audit, connect, engagement, now
from .normalize import persist_normalized
from .scope import target_allowed


METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def analyze_openapi(engagement_name: str, spec_path: Path) -> dict:
    """Offline contract review. It never sends requests to described servers."""
    document = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not (str(document.get("openapi", "")).startswith("3.") or "swagger" in document):
        raise ValueError("expected an OpenAPI/Swagger JSON document")
    servers = document.get("servers") or []
    hosts = {urlparse(s.get("url", "")).hostname for s in servers if isinstance(s, dict)} - {None}
    paths = document.get("paths") or {}
    findings = []
    operations = 0
    root_security = document.get("security")
    for route, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in METHODS or not isinstance(operation, dict):
                continue
            operations += 1
            security = operation.get("security", root_security)
            if security == [] or security is None:
                findings.append({"severity": "medium", "title": "API operation has no declared authentication", "details": {"method": method.upper(), "path": route, "confidence": 0.65}})
            parameters = list(path_item.get("parameters") or []) + list(operation.get("parameters") or [])
            if any(p.get("in") == "path" and str(p.get("name", "")).lower() in {"id", "user_id", "account_id", "object_id"} for p in parameters if isinstance(p, dict)):
                findings.append({"severity": "info", "title": "Object authorization review required", "details": {"method": method.upper(), "path": route, "confidence": 0.5}})
            body = ((operation.get("requestBody") or {}).get("content") or {})
            for media in body.values():
                schema = media.get("schema", {}) if isinstance(media, dict) else {}
                if isinstance(schema, dict) and schema.get("additionalProperties") is True:
                    findings.append({"severity": "low", "title": "API request permits unrestricted additional properties", "details": {"method": method.upper(), "path": route, "confidence": 0.7}})
    target = sorted(hosts)[0] if hosts else f"offline:{spec_path.name}"
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        outside = sorted(host for host in hosts if not target_allowed(host, scopes))
        if outside:
            raise PermissionError(f"API specification contains out-of-scope servers: {', '.join(outside)}")
        counts = persist_normalized(conn, eng["id"], "openapi-offline", target, {"entities": [], "findings": findings}, now())
        audit(conn, "api.openapi_analyzed", {"file": str(spec_path), "operations": operations, "findings": len(findings)}, eng["id"])
    return {"operations": operations, "servers": sorted(hosts), "observations": len(findings), "persisted": counts, "mode": "offline"}
