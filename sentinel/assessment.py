from __future__ import annotations

from .certification import certify
from .dashboard import build_dashboard
from .health import check_health
from .intelligence import attack_paths, score_engagement
from .report import build_report
from .validation import correlate_findings
from .vulnerability_intel import prioritize, validation_plan
from .workflow import create_workflow, run_workflow


def run_assessment(engagement: str, target: str, *, approve_active: bool = False, dry_run: bool = False) -> dict:
    """Run the complete reviewed pipeline sequentially under one policy decision."""
    stages = []
    preflight = certify(probe_versions=False, write=False)
    blocking_failures = [item["name"] for group in (preflight["adapters"], preflight["adapter_binaries"]) for item in group if item["status"] == "failed"]
    stages.append({"name": "preflight", "status": "completed" if not blocking_failures else "failed", "result": {**preflight["summary"], "blocking_failures": blocking_failures}})
    if blocking_failures:
        return {"engagement": engagement, "target": target, "dry_run": dry_run, "stages": stages, "completed": False, "reason": "preflight certification failed"}

    workflow_id = create_workflow(engagement, target, "complete-safe")
    execution = run_workflow(workflow_id, approve_active=approve_active, dry_run=dry_run)
    stages.append({"name": "collection-and-testing", "status": execution["status"], "result": execution})

    if dry_run or execution["status"] == "blocked":
        return {"engagement": engagement, "target": target, "dry_run": dry_run, "workflow_id": workflow_id, "stages": stages, "completed": False, "reason": "plan only" if dry_run else "policy blocked execution"}

    correlated = correlate_findings(engagement)
    stages.append({"name": "correlation", "status": "completed", "result": {"groups": len(correlated["groups"])}})

    general_risk = score_engagement(engagement)
    vulnerability_risk = prioritize(engagement)
    proof_plan = validation_plan(engagement)
    paths = attack_paths(engagement, target)
    stages.append({"name": "knowledge-graph-and-risk", "status": "completed", "result": {"scored_findings": len(general_risk["findings"]), "prioritized_vulnerabilities": len(vulnerability_risk["vulnerabilities"]), "validation_plans": len(proof_plan["plans"]), "attack_paths": len(paths["paths"])}})

    json_path, html_path = build_report(engagement)
    dashboard_path = build_dashboard(engagement)
    stages.append({"name": "reporting", "status": "completed", "result": {"json": str(json_path), "html": str(html_path), "dashboard": str(dashboard_path)}})

    health = check_health(engagement, False)
    stages.append({"name": "final-health", "status": "completed", "result": health})
    return {
        "engagement": engagement,
        "target": target,
        "dry_run": False,
        "workflow_id": workflow_id,
        "stages": stages,
        "completed": execution["status"] in {"completed", "completed_with_errors"},
        "workflow_status": execution["status"],
        "reports": {"json": str(json_path), "html": str(html_path), "dashboard": str(dashboard_path)},
        "policy": "Only reviewed adapters run. Missing adapters are skipped; active operations require engagement enablement and explicit approval.",
    }
