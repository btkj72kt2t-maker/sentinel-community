from __future__ import annotations

from .report import build_report
from .taxonomy import coverage_matrix
from .workflow import create_workflow, run_workflow
from .validation import correlate_findings
from .intelligence import score_engagement
from .dashboard import build_dashboard
from .vulnerability_intel import prioritize, validation_plan


HUNT_MODES = {
    "passive": ("passive",),
    "web": ("web-safe",),
    "network": ("network-safe",),
    "full-safe": ("web-safe", "network-safe"),
}


def run_hunt(engagement: str, target: str, mode: str = "full-safe", *, approve_active: bool = False, dry_run: bool = False) -> dict:
    if mode not in HUNT_MODES:
        raise ValueError(f"Unknown hunt mode: {mode}")
    workflows = []
    for profile in HUNT_MODES[mode]:
        workflow_id = create_workflow(engagement, target, profile)
        workflows.append(run_workflow(workflow_id, approve_active=approve_active, dry_run=dry_run))
    report = None
    if not dry_run:
        validation = correlate_findings(engagement)
        scores = score_engagement(engagement)
        vulnerability_priority = prioritize(engagement)
        proof_plan = validation_plan(engagement)
        json_path, html_path = build_report(engagement)
        dashboard_path = build_dashboard(engagement)
        report = {"json": str(json_path), "html": str(html_path), "dashboard": str(dashboard_path)}
    else:
        validation, scores, vulnerability_priority, proof_plan = None, None, None, None
    return {"engagement": engagement, "target": target, "mode": mode, "workflows": workflows, "coverage": coverage_matrix()["summary"], "validation": validation, "risk": scores, "vulnerability_priority": vulnerability_priority, "validation_plan": proof_plan, "report": report}
