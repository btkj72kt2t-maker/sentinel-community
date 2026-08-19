from __future__ import annotations

from dataclasses import dataclass

from .db import audit, connect, engagement, now
from .policy import execution_decision
from .scope import normalize_target, target_allowed
from .tools import REGISTRY, command_for, execute
from .normalize import normalize, persist_normalized


@dataclass(frozen=True)
class WorkflowStep:
    tool: str
    profile: str


PROFILES: dict[str, tuple[WorkflowStep, ...]] = {
    "passive": (
        WorkflowStep("dig", "default"),
        WorkflowStep("whois", "default"),
        WorkflowStep("subfinder", "passive"),
    ),
    "web-safe": (
        WorkflowStep("dig", "default"),
        WorkflowStep("whois", "default"),
        WorkflowStep("subfinder", "passive"),
        WorkflowStep("httpx", "safe"),
        WorkflowStep("whatweb", "safe"),
        WorkflowStep("testssl.sh", "safe"),
        WorkflowStep("nuclei", "safe"),
    ),
    "network-safe": (
        WorkflowStep("dig", "default"),
        WorkflowStep("nmap", "safe"),
    ),
}


def create_workflow(engagement_name: str, target: str, profile: str) -> int:
    if profile not in PROFILES:
        raise ValueError(f"Unknown workflow profile: {profile}")
    host = normalize_target(target)
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        if not target_allowed(host, scopes):
            audit(conn, "scope.denied", {"target": host, "workflow": profile}, eng["id"])
            raise PermissionError(f"{host} is outside engagement scope")
        cur = conn.execute(
            "INSERT INTO workflows(engagement_id,profile,target,status,created_at,updated_at) VALUES(?,?,?,'pending',?,?)",
            (eng["id"], profile, host, now(), now()),
        )
        workflow_id = cur.lastrowid
        for position, step in enumerate(PROFILES[profile]):
            conn.execute(
                "INSERT INTO workflow_steps(workflow_id,position,tool,profile) VALUES(?,?,?,?)",
                (workflow_id, position, step.tool, step.profile),
            )
        audit(conn, "workflow.created", {"workflow_id": workflow_id, "profile": profile, "target": host}, eng["id"])
    return workflow_id


def run_workflow(workflow_id: int, *, approve_active: bool = False, dry_run: bool = False) -> dict:
    with connect() as conn:
        flow = conn.execute("SELECT * FROM workflows WHERE id=?", (workflow_id,)).fetchone()
        if not flow:
            raise ValueError(f"Unknown workflow: {workflow_id}")
        eng = conn.execute("SELECT * FROM engagements WHERE id=?", (flow["engagement_id"],)).fetchone()
        if eng["kill_switch"]:
            raise PermissionError("engagement kill switch is active")
        steps = conn.execute("SELECT * FROM workflow_steps WHERE workflow_id=? ORDER BY position", (workflow_id,)).fetchall()
        conn.execute("UPDATE workflows SET status='running',updated_at=? WHERE id=?", (now(), workflow_id))
        audit(conn, "workflow.started", {"workflow_id": workflow_id, "dry_run": dry_run}, eng["id"])

    summary = {"workflow_id": workflow_id, "target": flow["target"], "profile": flow["profile"], "steps": []}
    final_status = "completed"
    for step in steps:
        if step["status"] == "completed":
            summary["steps"].append({"tool": step["tool"], "status": "already_completed"})
            continue
        with connect() as conn:
            eng = conn.execute("SELECT * FROM engagements WHERE id=?", (flow["engagement_id"],)).fetchone()
            spec = REGISTRY[step["tool"]]
            decision = execution_decision(eng, active=spec.active and not dry_run, approved=approve_active)
            if not decision.allowed:
                conn.execute("UPDATE workflow_steps SET status='blocked',message=? WHERE id=?", (decision.reason, step["id"]))
                conn.execute("UPDATE workflows SET status='blocked',updated_at=? WHERE id=?", (now(), workflow_id))
                audit(conn, "workflow.blocked", {"workflow_id": workflow_id, "tool": spec.name, "reason": decision.reason}, eng["id"])
                summary["steps"].append({"tool": spec.name, "status": "blocked", "message": decision.reason})
                final_status = "blocked"
                break
            try:
                _, command = command_for(step["tool"], step["profile"], flow["target"])
            except RuntimeError as exc:
                conn.execute("UPDATE workflow_steps SET status='skipped',message=? WHERE id=?", (str(exc), step["id"]))
                summary["steps"].append({"tool": spec.name, "status": "skipped", "message": str(exc)})
                continue
            if dry_run:
                summary["steps"].append({"tool": spec.name, "status": "planned", "command": command[1:]})
                continue
            cur = conn.execute(
                "INSERT INTO tool_runs(engagement_id,tool,profile,target,command,status,started_at) VALUES(?,?,?,?,?,'running',?)",
                (eng["id"], spec.name, step["profile"], flow["target"], " ".join(command[1:]), now()),
            )
            run_id = cur.lastrowid
            conn.execute("UPDATE workflow_steps SET status='running',tool_run_id=? WHERE id=?", (run_id, step["id"]))
        result = execute(step["tool"], step["profile"], flow["target"], run_id)
        status = "completed" if result["exit_code"] == 0 else "failed"
        with connect() as conn:
            counts = persist_normalized(conn, flow["engagement_id"], spec.name, flow["target"], normalize(spec.name, result["stdout_path"], flow["target"]), now())
            conn.execute("UPDATE tool_runs SET status=?,exit_code=?,stdout_path=?,stderr_path=?,finished_at=? WHERE id=?", (status, result["exit_code"], result["stdout_path"], result["stderr_path"], now(), run_id))
            conn.execute("UPDATE workflow_steps SET status=?,message=? WHERE id=?", (status, result.get("stderr_preview", "")[:1000], step["id"]))
            conn.execute("UPDATE workflows SET current_step=?,updated_at=? WHERE id=?", (step["position"] + 1, now(), workflow_id))
        summary["steps"].append({"tool": spec.name, "status": status, "run_id": run_id, "normalized": counts})
        if status == "failed":
            final_status = "completed_with_errors"
    with connect() as conn:
        conn.execute("UPDATE workflows SET status=?,updated_at=? WHERE id=?", (final_status, now(), workflow_id))
        audit(conn, "workflow.finished", {"workflow_id": workflow_id, "status": final_status}, flow["engagement_id"])
    summary["status"] = final_status
    return summary
