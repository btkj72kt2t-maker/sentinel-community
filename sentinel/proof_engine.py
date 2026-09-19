from __future__ import annotations

import json

from .db import audit, connect, engagement, now
from .policy import execution_decision
from .proof_modules import select_modules


def plan_proof(name: str, finding_id: int) -> dict:
    with connect() as conn:
        eng = engagement(conn, name)
        finding = conn.execute("SELECT * FROM findings WHERE id=? AND engagement_id=?", (finding_id, eng["id"])).fetchone()
        if not finding:
            raise ValueError("finding does not belong to this engagement")
        modules = select_modules(finding["title"], finding["details"])
        plan = [{"module_id": m.module_id, "family": m.family, "mode": m.mode, "max_requests": m.max_requests, "side_effects": m.side_effects, "evidence": list(m.evidence), "cleanup": m.cleanup} for m in modules]
        audit(conn, "proof.planned", {"finding_id": finding_id, "modules": [m.module_id for m in modules]}, eng["id"])
    return {"engagement": name, "finding_id": finding_id, "target": finding["target"], "modules": plan, "policy": "Planning never executes an exploit. Lab-only modules require lab mode and explicit approval."}


def start_proof(name: str, finding_id: int, module_id: str, *, approved: bool = False) -> dict:
    plan = plan_proof(name, finding_id)
    module = next((item for item in plan["modules"] if item["module_id"] == module_id), None)
    if not module:
        raise ValueError("module is not eligible for this finding")
    lab_only = module["mode"] in {"lab-only", "offline-or-lab"}
    with connect() as conn:
        eng = engagement(conn, name)
        decision = execution_decision(eng, active=module["max_requests"] > 0, lab_only=lab_only, approved=approved)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        cur = conn.execute("INSERT INTO proof_runs(engagement_id,finding_id,module_id,mode,status,request_budget,result,created_at) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], finding_id, module_id, module["mode"], "ready", module["max_requests"], json.dumps({"plan": module}, sort_keys=True), now()))
        audit(conn, "proof.ready", {"proof_run_id": cur.lastrowid, "finding_id": finding_id, "module_id": module_id}, eng["id"])
        run_id = cur.lastrowid
    return {"proof_run_id": run_id, "status": "ready", "module": module, "note": "Ready means policy gates passed; module-specific evidence must still be supplied or collected."}


def list_proof_runs(name: str) -> list[dict]:
    with connect() as conn:
        eng = engagement(conn, name)
        return [dict(row) for row in conn.execute("SELECT * FROM proof_runs WHERE engagement_id=? ORDER BY id", (eng["id"],))]
