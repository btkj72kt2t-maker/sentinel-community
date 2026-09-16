from __future__ import annotations

import json
from pathlib import Path

from .db import audit, connect, engagement, now
from .vulnerability_intel import CVE_PATTERN


def import_cyclonedx(name: str, path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or not isinstance(document.get("components", []), list):
        raise ValueError("expected a CycloneDX JSON BOM")
    components, links = 0, 0
    refs = {}
    with connect() as conn:
        eng = engagement(conn, name)
        for item in document.get("components") or []:
            bom_ref = str(item.get("bom-ref") or item.get("purl") or f"{item.get('name')}@{item.get('version', '')}")
            if not item.get("name"):
                continue
            cur = conn.execute("INSERT INTO components(engagement_id,bom_ref,name,version,purl,component_type,attributes,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(engagement_id,bom_ref) DO UPDATE SET name=excluded.name,version=excluded.version,purl=excluded.purl,component_type=excluded.component_type,attributes=excluded.attributes RETURNING id", (eng["id"], bom_ref, str(item["name"]), item.get("version"), item.get("purl"), item.get("type"), json.dumps(item, sort_keys=True), now()))
            refs[bom_ref] = cur.fetchone()[0]
            components += 1
        for vulnerability in document.get("vulnerabilities") or []:
            cve = str(vulnerability.get("id") or "").upper()
            if not CVE_PATTERN.fullmatch(cve):
                continue
            analysis = vulnerability.get("analysis") or {}
            status = str(analysis.get("state") or "unknown")
            response = ",".join(str(value) for value in analysis.get("response") or [])
            conn.execute("INSERT INTO vulnerability_intelligence(cve,attributes,updated_at) VALUES(?,?,?) ON CONFLICT(cve) DO UPDATE SET updated_at=excluded.updated_at", (cve, json.dumps({"cyclonedx": vulnerability}, sort_keys=True), now()))
            for affected in vulnerability.get("affects") or []:
                component_id = refs.get(str(affected.get("ref")))
                if component_id:
                    conn.execute("INSERT INTO component_vulnerabilities(component_id,cve,vex_status,justification,response,source,updated_at) VALUES(?,?,?,?,?,'CycloneDX',?) ON CONFLICT(component_id,cve,source) DO UPDATE SET vex_status=excluded.vex_status,justification=excluded.justification,response=excluded.response,updated_at=excluded.updated_at", (component_id, cve, status, analysis.get("justification"), response, now()))
                    links += 1
        audit(conn, "supply_chain.cyclonedx_imported", {"file": str(path), "components": components, "vulnerability_links": links}, eng["id"])
    return {"format": "CycloneDX", "components": components, "vulnerability_links": links}


def import_csaf(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    category = str((document.get("document") or {}).get("category") or "")
    if not category or not isinstance(document.get("vulnerabilities", []), list):
        raise ValueError("expected a CSAF JSON advisory")
    imported = 0
    with connect() as conn:
        for vulnerability in document.get("vulnerabilities") or []:
            cve = str(vulnerability.get("cve") or "").upper()
            if not CVE_PATTERN.fullmatch(cve):
                continue
            remediations = vulnerability.get("remediations") or []
            action = "; ".join(str(item.get("details")) for item in remediations if item.get("details"))[:4000] or None
            attributes = {"csaf": {"title": vulnerability.get("title"), "product_status": vulnerability.get("product_status"), "flags": vulnerability.get("flags"), "notes": vulnerability.get("notes")}, "document_category": category}
            conn.execute("INSERT INTO vulnerability_intelligence(cve,required_action,attributes,updated_at) VALUES(?,?,?,?) ON CONFLICT(cve) DO UPDATE SET required_action=COALESCE(excluded.required_action,vulnerability_intelligence.required_action),attributes=excluded.attributes,updated_at=excluded.updated_at", (cve, action, json.dumps(attributes, sort_keys=True), now()))
            imported += 1
        audit(conn, "intelligence.csaf_imported", {"file": str(path), "category": category, "vulnerabilities": imported})
    return {"format": "CSAF", "category": category, "vulnerabilities": imported}


def component_risk(name: str) -> dict:
    with connect() as conn:
        eng = engagement(conn, name)
        rows = [dict(row) for row in conn.execute("SELECT c.name,c.version,c.purl,cv.cve,cv.vex_status,cv.justification,cv.response,v.kev,v.epss,v.required_action FROM component_vulnerabilities cv JOIN components c ON c.id=cv.component_id JOIN vulnerability_intelligence v ON v.cve=cv.cve WHERE c.engagement_id=? ORDER BY v.kev DESC,v.epss DESC", (eng["id"],))]
    for row in rows:
        status = row["vex_status"].lower()
        row["priority"] = "not-affected" if status in {"not_affected", "false_positive"} else "critical" if row["kev"] else "high" if float(row["epss"] or 0) >= 0.5 else "review"
    return {"engagement": name, "components": rows, "warning": "VEX status and local reachability must be verified before remediation decisions."}
