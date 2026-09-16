from __future__ import annotations

import json
from pathlib import Path

from .db import audit, connect, engagement, now
from .normalize import persist_normalized


LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def import_sarif(engagement_name: str, path: Path) -> dict:
    """Import standardized offline results from SAST, SCA, IaC and cloud tools."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not str(document.get("version", "")).startswith("2.1"):
        raise ValueError("expected SARIF 2.1 JSON")
    grouped: dict[tuple[str, str], list[dict]] = {}
    tools = set()
    for run in document.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = str(driver.get("name") or "sarif-import")
        tools.add(tool)
        rules = {str(rule.get("id")): rule for rule in driver.get("rules") or []}
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "unclassified")
            message = str((result.get("message") or {}).get("text") or rules.get(rule_id, {}).get("name") or rule_id)
            locations = result.get("locations") or []
            uri = "offline-artifact"
            if locations:
                uri = str((((locations[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")) or uri)
            finding = {"severity": LEVELS.get(str(result.get("level", "warning")).lower(), "medium"), "title": f"{rule_id}: {message}"[:500], "details": {"rule_id": rule_id, "location": uri, "source_file": str(path), "confidence": 0.7}}
            grouped.setdefault((tool, uri), []).append(finding)
    persisted = 0
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        for (tool, target), findings in grouped.items():
            persisted += persist_normalized(conn, eng["id"], tool, target, {"entities": [], "findings": findings}, now())["findings"]
        audit(conn, "results.sarif_imported", {"file": str(path), "tools": sorted(tools), "findings": persisted}, eng["id"])
    return {"format": "SARIF 2.1", "tools": sorted(tools), "findings": persisted, "mode": "offline-import"}
