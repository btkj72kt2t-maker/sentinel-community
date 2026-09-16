from __future__ import annotations

import json
import ipaddress
import uuid
from pathlib import Path

from .db import audit, connect, engagement, now


TYPE_MAP = {"domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip", "software": "software", "vulnerability": "vulnerability", "indicator": "indicator", "threat-actor": "threat", "intrusion-set": "threat", "malware": "malware"}


def _value(obj: dict) -> str:
    if obj.get("type") == "vulnerability":
        for reference in obj.get("external_references") or []:
            if str(reference.get("external_id", "")).upper().startswith("CVE-"):
                return str(reference["external_id"]).upper()
    return str(obj.get("value") or obj.get("name") or obj.get("id"))


def import_stix(name: str, path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("type") != "bundle" or not isinstance(document.get("objects"), list):
        raise ValueError("expected a STIX 2.1 JSON bundle")
    created, relationships, refs = 0, 0, {}
    with connect() as conn:
        eng = engagement(conn, name)
        for obj in document["objects"]:
            stix_id, object_type = str(obj.get("id", "")), str(obj.get("type", ""))
            if "--" not in stix_id or not object_type:
                continue
            conn.execute("INSERT INTO stix_objects(engagement_id,stix_id,object_type,object_json,created_at) VALUES(?,?,?,?,?) ON CONFLICT(engagement_id,stix_id) DO UPDATE SET object_json=excluded.object_json", (eng["id"], stix_id, object_type, json.dumps(obj, sort_keys=True), now()))
            if object_type in TYPE_MAP:
                value = _value(obj)
                row = conn.execute("SELECT id FROM entities WHERE engagement_id=? AND kind=? AND value=?", (eng["id"], TYPE_MAP[object_type], value)).fetchone()
                entity_id = row["id"] if row else conn.execute("INSERT INTO entities(engagement_id,kind,value,attributes,created_at) VALUES(?,?,?,?,?)", (eng["id"], TYPE_MAP[object_type], value, json.dumps({"stix_id": stix_id}, sort_keys=True), now())).lastrowid
                refs[stix_id] = entity_id
                created += int(row is None)
        for obj in document["objects"]:
            if obj.get("type") != "relationship":
                continue
            source, target = refs.get(obj.get("source_ref")), refs.get(obj.get("target_ref"))
            if source and target:
                conn.execute("INSERT INTO relationships(engagement_id,source_id,target_id,relation,confidence,evidence,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(engagement_id,source_id,target_id,relation) DO UPDATE SET evidence=excluded.evidence", (eng["id"], source, target, str(obj.get("relationship_type") or "related-to"), 0.8, json.dumps({"stix_id": obj.get("id")}), now()))
                relationships += 1
        audit(conn, "intelligence.stix_imported", {"file": str(path), "objects": len(document["objects"]), "entities": created, "relationships": relationships}, eng["id"])
    return {"objects": len(document["objects"]), "entities_created": created, "relationships_created": relationships}


def export_stix(name: str, path: Path) -> dict:
    objects = []
    with connect() as conn:
        eng = engagement(conn, name)
        for row in conn.execute("SELECT * FROM entities WHERE engagement_id=?", (eng["id"],)):
            if row["kind"] == "ip":
                stix_type = "ipv4-addr" if ipaddress.ip_address(row["value"]).version == 4 else "ipv6-addr"
            else:
                stix_type = {"domain": "domain-name", "software": "software", "vulnerability": "vulnerability"}.get(row["kind"])
            if not stix_type:
                continue
            stable_name = f"sentinel:{name}:{row['kind']}:{row['value']}"
            stix_id = f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, stable_name)}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id}
            if stix_type in {"domain-name", "ipv4-addr", "ipv6-addr"}:
                obj["value"] = row["value"]
            elif stix_type == "vulnerability":
                obj["name"] = row["value"]
                obj["external_references"] = [{"source_name": "cve", "external_id": row["value"]}]
            else:
                obj["name"] = row["value"]
            objects.append(obj)
        audit(conn, "intelligence.stix_exported", {"file": str(path), "objects": len(objects)}, eng["id"])
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return {"path": str(path), "objects": len(objects)}
