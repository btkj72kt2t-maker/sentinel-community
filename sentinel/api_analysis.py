from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from .db import audit, connect, engagement, now
from .normalize import persist_normalized
from .scope import target_allowed


METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _persist_observations(engagement_name: str, source: str, target: str, findings: list[dict], audit_action: str, audit_data: dict) -> dict:
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        counts = persist_normalized(conn, eng["id"], source, target, {"entities": [], "findings": findings}, now())
        audit(conn, audit_action, audit_data, eng["id"])
    return counts


def analyze_openapi(engagement_name: str, spec_path: Path) -> dict:
    """Offline contract review. It never sends requests to described servers."""
    document = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not (str(document.get("openapi", "")).startswith("3.") or "swagger" in document):
        raise ValueError("expected an OpenAPI/Swagger JSON document")
    servers = document.get("servers") or []
    if not isinstance(servers, list):
        raise ValueError("OpenAPI servers must be an array")
    hosts = {urlparse(str(s.get("url", ""))).hostname for s in servers if isinstance(s, dict)} - {None}
    paths = document.get("paths") or {}
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")
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


def analyze_asyncapi(engagement_name: str, spec_path: Path) -> dict:
    """Offline AsyncAPI contract review; it never opens a broker connection."""
    document = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not str(document.get("asyncapi", "")).startswith(("2.", "3.")):
        raise ValueError("expected an AsyncAPI 2.x or 3.x JSON document")
    servers = document.get("servers") or {}
    if not isinstance(servers, dict):
        raise ValueError("AsyncAPI servers must be an object")
    hosts = set()
    findings = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        raw = str(server.get("url") or "")
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
        protocol = str(server.get("protocol") or "").lower()
        if protocol in {"ws", "mqtt", "amqp", "kafka"} and not server.get("security"):
            findings.append({"severity": "medium", "title": "Message broker server has no declared security requirement", "details": {"server": name, "protocol": protocol}})
        if protocol in {"ws", "mqtt", "amqp", "http"}:
            findings.append({"severity": "low", "title": "Unencrypted asynchronous transport declared", "details": {"server": name, "protocol": protocol}})
    channels = document.get("channels") or {}
    if not isinstance(channels, dict):
        raise ValueError("AsyncAPI channels must be an object")
    operations = 0
    for channel_name, channel in channels.items():
        if not isinstance(channel, dict):
            continue
        for operation in ("publish", "subscribe", "send", "receive"):
            value = channel.get(operation)
            if isinstance(value, dict):
                operations += 1
                if value.get("security") == []:
                    findings.append({"severity": "medium", "title": "Asynchronous operation explicitly disables security", "details": {"channel": channel_name, "operation": operation}})
    declared_operations = document.get("operations") or {}
    if not isinstance(declared_operations, dict):
        raise ValueError("AsyncAPI operations must be an object")
    for operation_name, value in declared_operations.items():
        if not isinstance(value, dict):
            continue
        operations += 1
        if value.get("security") == []:
            findings.append({"severity": "medium", "title": "Asynchronous operation explicitly disables security", "details": {"operation": operation_name, "action": value.get("action")}})
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        outside = sorted(host for host in hosts if not target_allowed(host, scopes))
        if outside:
            raise PermissionError(f"AsyncAPI specification contains out-of-scope servers: {', '.join(outside)}")
    target = sorted(hosts)[0] if hosts else f"offline:{spec_path.name}"
    counts = _persist_observations(engagement_name, "asyncapi-offline", target, findings, "api.asyncapi_analyzed", {"file": str(spec_path), "operations": operations, "findings": len(findings)})
    return {"operations": operations, "channels": len(channels), "servers": sorted(hosts), "observations": len(findings), "persisted": counts, "mode": "offline"}


def analyze_graphql_schema(engagement_name: str, schema_path: Path) -> dict:
    """Review a saved GraphQL introspection result without issuing queries."""
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    data = document.get("data") if isinstance(document, dict) else None
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        raise ValueError("expected a GraphQL introspection JSON response")
    types = [item for item in schema.get("types") or [] if isinstance(item, dict)]
    mutation_name = (schema.get("mutationType") or {}).get("name")
    mutation_fields = []
    for item in types:
        if item.get("name") == mutation_name:
            mutation_fields = [str(field.get("name")) for field in item.get("fields") or [] if isinstance(field, dict)]
            break
    sensitive = sorted(name for name in mutation_fields if any(token in name.lower() for token in ("delete", "admin", "role", "permission", "password", "token", "transfer", "payment")))
    findings = []
    if mutation_fields:
        findings.append({"severity": "info", "title": "GraphQL mutations require object and function authorization review", "details": {"mutation_count": len(mutation_fields), "sensitive_operation_names": sensitive[:100]}})
    if len(types) > 250:
        findings.append({"severity": "info", "title": "Large GraphQL schema requires query-cost and depth-limit review", "details": {"type_count": len(types)}})
    counts = _persist_observations(engagement_name, "graphql-offline", f"offline:{schema_path.name}", findings, "api.graphql_analyzed", {"file": str(schema_path), "types": len(types), "mutations": len(mutation_fields), "findings": len(findings)})
    return {"types": len(types), "mutations": len(mutation_fields), "sensitive_mutation_names": sensitive[:100], "observations": len(findings), "persisted": counts, "mode": "offline", "introspection_execution": False}
