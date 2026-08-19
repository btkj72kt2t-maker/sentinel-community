from __future__ import annotations

import json
from collections import deque

from .db import audit, connect, engagement, now

SEVERITY_WEIGHT = {"info": 5.0, "low": 20.0, "medium": 45.0, "high": 75.0, "critical": 95.0}


def score_engagement(name: str) -> dict:
    with connect() as conn:
        eng = engagement(conn, name)
        findings = conn.execute("SELECT * FROM findings WHERE engagement_id=? AND status!='closed'", (eng["id"],)).fetchall()
        services = conn.execute("SELECT value,attributes FROM entities WHERE engagement_id=? AND kind='service'", (eng["id"],)).fetchall()
        service_exposure = min(10.0, len(services) * 0.5)
        updated = []
        for row in findings:
            details = json.loads(row["details"] or "{}")
            base = SEVERITY_WEIGHT.get(row["severity"].lower(), 5.0)
            confidence = float(details.get("confidence", 0.8)) if isinstance(details, dict) else 0.8
            confidence = max(0.1, min(confidence, 1.0))
            recurrence = min(5.0, max(0, row["occurrences"] - 1) * 0.5)
            score = round(min(100.0, base * confidence + service_exposure + recurrence), 1)
            conn.execute("UPDATE findings SET risk_score=? WHERE id=?", (score, row["id"]))
            updated.append({"id": row["id"], "title": row["title"], "score": score, "factors": {"severity": base, "confidence": confidence, "service_exposure": service_exposure, "recurrence": recurrence}})
        audit(conn, "intelligence.scored", {"findings": len(updated)}, eng["id"])
    return {"engagement": name, "findings": sorted(updated, key=lambda x: x["score"], reverse=True)}


def attack_paths(name: str, source_value: str | None = None, max_depth: int = 5) -> dict:
    with connect() as conn:
        eng = engagement(conn, name)
        entities = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM entities WHERE engagement_id=?", (eng["id"],))}
        relations = [dict(r) for r in conn.execute("SELECT * FROM relationships WHERE engagement_id=?", (eng["id"],))]
    adjacency: dict[int, list[tuple[int, str, float]]] = {}
    for edge in relations:
        adjacency.setdefault(edge["source_id"], []).append((edge["target_id"], edge["relation"], edge["confidence"]))
    starts = [eid for eid, entity in entities.items() if source_value is None or entity["value"] == source_value]
    paths = []
    for start in starts:
        queue = deque([(start, [start], [], 1.0)])
        while queue:
            current, nodes, edges, confidence = queue.popleft()
            if edges:
                paths.append({"nodes": [entities[n]["value"] for n in nodes], "relations": edges, "confidence": round(confidence, 3)})
            if len(edges) >= max_depth:
                continue
            for target, relation, edge_confidence in adjacency.get(current, []):
                if target not in nodes:
                    queue.append((target, nodes + [target], edges + [relation], confidence * edge_confidence))
    paths.sort(key=lambda p: (len(p["relations"]), p["confidence"]), reverse=True)
    return {"engagement": name, "paths": paths[:100]}

