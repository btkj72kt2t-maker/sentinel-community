from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _json_lines(text: str):
    for line in text.splitlines():
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue


def normalize(tool: str, output_path: str, target: str) -> dict:
    text = Path(output_path).read_text(encoding="utf-8", errors="replace")
    entities: list[dict] = []
    findings: list[dict] = []
    if tool == "dig":
        for value in re.findall(r"\s(IN\s+)?(?:A|AAAA)\s+([^\s]+)", text):
            address = value[1].rstrip(".")
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            entities.append({"kind": "ip", "value": address, "attributes": {"source": "dig"}})
    elif tool == "subfinder":
        for item in _json_lines(text):
            host = item.get("host") or item.get("name")
            if host:
                entities.append({"kind": "domain", "value": str(host).lower().rstrip("."), "attributes": item})
    elif tool == "httpx":
        for item in _json_lines(text):
            host = item.get("host") or item.get("input") or item.get("url")
            if host:
                entities.append({"kind": "web_service", "value": str(host), "attributes": item})
    elif tool == "nuclei":
        for item in _json_lines(text):
            info = item.get("info") or {}
            severity = str(info.get("severity", "info")).lower()
            findings.append({
                "severity": severity if severity in SEVERITIES else "info",
                "title": str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                "details": item,
            })
    elif tool == "nmap" and text.strip():
        for value in re.findall(r'<address\s+[^>]*addr="([^"]+)"', text):
            entities.append({"kind": "ip", "value": value, "attributes": {"source": "nmap"}})
        for match in re.finditer(r'<port\s+protocol="([^"]+)"\s+portid="([^"]+)"[^>]*>(.*?)</port>', text, re.DOTALL):
            protocol, port_id, body = match.groups()
            if not re.search(r'<state\s+[^>]*state="open"', body):
                continue
            service_match = re.search(r'<service\s+([^>]*)/?>', body)
            attributes = {k: v for k, v in re.findall(r'(\w+)="([^"]*)"', service_match.group(1))} if service_match else {}
            entities.append({"kind": "service", "value": f"{target}:{port_id}/{protocol}", "attributes": attributes})
    return {"entities": entities, "findings": findings}


def persist_normalized(conn, engagement_id: int, tool: str, target: str, normalized: dict, timestamp: str) -> dict:
    entity_count = 0
    finding_count = 0
    for entity in normalized["entities"]:
        conn.execute(
            "INSERT INTO entities(engagement_id,kind,value,attributes,created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(engagement_id,kind,value) DO UPDATE SET attributes=excluded.attributes",
            (engagement_id, entity["kind"], entity["value"], json.dumps(entity.get("attributes", {}), sort_keys=True), timestamp),
        )
        entity_count += 1
    for finding in normalized["findings"]:
        conn.execute(
            "INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (engagement_id, target, tool, finding["severity"], finding["title"], json.dumps(finding.get("details", {}), sort_keys=True), timestamp),
        )
        finding_count += 1
    return {"entities": entity_count, "findings": finding_count}
