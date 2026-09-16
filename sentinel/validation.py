from __future__ import annotations

import json
import re

from .db import audit, connect, engagement


def _canonical(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def correlate_findings(name: str) -> dict:
    """Correlate equivalent observations without generating exploit traffic."""
    with connect() as conn:
        eng = engagement(conn, name)
        rows = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE engagement_id=?", (eng["id"],))]
        groups: dict[tuple[str, str], list[dict]] = {}
        for row in rows:
            groups.setdefault((row["target"], _canonical(row["title"])), []).append(row)
        results = []
        for (target, title), members in groups.items():
            sources = sorted({m["source"] for m in members})
            occurrences = sum(int(m.get("occurrences", 1)) for m in members)
            status = "confirmed" if len(sources) >= 2 else ("reproduced" if occurrences >= 2 else "unverified")
            confidence = min(0.99, 0.45 + 0.2 * len(sources) + 0.1 * min(occurrences - 1, 3))
            for member in members:
                details = json.loads(member.get("details") or "{}")
                if not isinstance(details, dict):
                    details = {"raw": details}
                details["validation"] = {"status": status, "confidence": round(confidence, 2), "sources": sources, "occurrences": occurrences}
                conn.execute("UPDATE findings SET status=?,details=? WHERE id=?", (status, json.dumps(details, sort_keys=True), member["id"]))
            results.append({"target": target, "title": title, "status": status, "confidence": round(confidence, 2), "sources": sources, "finding_ids": [m["id"] for m in members]})
        audit(conn, "validation.correlated", {"groups": len(results)}, eng["id"])
    return {"engagement": name, "groups": sorted(results, key=lambda x: x["confidence"], reverse=True)}
