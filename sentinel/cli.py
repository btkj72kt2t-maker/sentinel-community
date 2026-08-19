from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from .config import evidence_dir
from .db import audit, connect, engagement, initialize, now
from .recon import nmap_recon, passive_recon
from .report import build_report
from .scope import classify_scope, normalize_target, target_allowed
from .tools import REGISTRY, command_for, execute, inventory
from .policy import execution_decision
from .workflow import PROFILES, create_workflow, run_workflow
from .normalize import normalize, persist_normalized
from .intelligence import attack_paths, score_engagement
from .jobs import enqueue_workflow, list_jobs, run_next


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Authorized security investigation workspace")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    ep = sub.add_parser("engagement")
    es = ep.add_subparsers(dest="engagement_command", required=True)
    create = es.add_parser("create")
    create.add_argument("name")
    create.add_argument("--domain", action="append", default=[])
    create.add_argument("--ip", action="append", default=[])
    create.add_argument("--allow-subdomains", action="store_true")
    create.add_argument("--enable-active", action="store_true")
    create.add_argument("--lab-mode", action="store_true", help="Marks an isolated cyber-range engagement")
    create.add_argument("--max-rate", type=int, default=25)
    es.add_parser("list")
    kill = es.add_parser("kill")
    kill.add_argument("name")
    resume = es.add_parser("resume")
    resume.add_argument("name")
    recon = sub.add_parser("recon")
    recon.add_argument("engagement")
    recon.add_argument("target")
    recon.add_argument("--active", action="store_true", help="Run a rate-limited Nmap service scan")
    ev = sub.add_parser("evidence")
    ev.add_argument("engagement")
    ev.add_argument("file", type=Path)
    rep = sub.add_parser("report")
    rep.add_argument("engagement")
    tools = sub.add_parser("tools")
    ts = tools.add_subparsers(dest="tools_command", required=True)
    ts.add_parser("list")
    run = ts.add_parser("run")
    run.add_argument("engagement")
    run.add_argument("tool", choices=sorted(REGISTRY))
    run.add_argument("target")
    run.add_argument("--profile", help="Adapter profile (defaults to safe, passive, or default)")
    run.add_argument("--approve-active", action="store_true")
    run.add_argument("--timeout", type=int, default=600)
    workflow = sub.add_parser("workflow")
    ws = workflow.add_subparsers(dest="workflow_command", required=True)
    ws.add_parser("profiles")
    wc = ws.add_parser("create")
    wc.add_argument("engagement")
    wc.add_argument("profile", choices=sorted(PROFILES))
    wc.add_argument("target")
    wr = ws.add_parser("run")
    wr.add_argument("workflow_id", type=int)
    wr.add_argument("--approve-active", action="store_true")
    wr.add_argument("--dry-run", action="store_true")
    intel = sub.add_parser("intel")
    ins = intel.add_subparsers(dest="intel_command", required=True)
    score = ins.add_parser("score")
    score.add_argument("engagement")
    paths = ins.add_parser("paths")
    paths.add_argument("engagement")
    paths.add_argument("--source")
    paths.add_argument("--max-depth", type=int, default=5)
    jobs = sub.add_parser("jobs")
    js = jobs.add_subparsers(dest="jobs_command", required=True)
    jq = js.add_parser("enqueue")
    jq.add_argument("engagement")
    jq.add_argument("workflow_id", type=int)
    jq.add_argument("--approve-active", action="store_true")
    jl = js.add_parser("list")
    jl.add_argument("engagement")
    jr = js.add_parser("run-next")
    jr.add_argument("engagement")
    return p


def create_engagement(args) -> None:
    with connect() as conn:
        cur = conn.execute("INSERT INTO engagements(name,active_enabled,lab_mode,max_rate,created_at) VALUES(?,?,?,?,?)", (args.name, int(args.enable_active), int(args.lab_mode), max(1, min(args.max_rate, 100)), now()))
        eid = cur.lastrowid
        for value in args.domain + args.ip:
            kind, normalized = classify_scope(value)
            conn.execute("INSERT INTO scope(engagement_id,kind,value,allow_subdomains) VALUES(?,?,?,?)", (eid, kind, normalized, int(args.allow_subdomains and kind == "domain")))
        audit(conn, "engagement.created", {"name": args.name, "active_enabled": args.enable_active, "lab_mode": args.lab_mode, "max_rate": max(1, min(args.max_rate, 100))}, eid)
    print(f"Created engagement {args.name}")


def run_recon(args) -> None:
    host = normalize_target(args.target)
    with connect() as conn:
        eng = engagement(conn, args.engagement)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        if not target_allowed(host, scopes):
            audit(conn, "scope.denied", {"target": host, "active": args.active}, eng["id"])
            raise SystemExit(f"Denied: {host} is outside engagement scope")
        if args.active and not eng["active_enabled"]:
            raise SystemExit("Denied: active scanning is disabled for this engagement")
        audit(conn, "recon.started", {"target": host, "active": args.active}, eng["id"])
    result = nmap_recon(host) if args.active else passive_recon(host)
    with connect() as conn:
        eng = engagement(conn, args.engagement)
        conn.execute("INSERT OR IGNORE INTO entities(engagement_id,kind,value,attributes,created_at) VALUES(?,?,?,?,?)", (eng["id"], "domain", host, json.dumps(result), now()))
        audit(conn, "recon.completed", {"target": host, "active": args.active, "errors": result.get("errors", [])}, eng["id"])
    print(json.dumps(result, indent=2))


def add_evidence(args) -> None:
    source = args.file.resolve()
    if not source.is_file():
        raise SystemExit(f"Not a file: {source}")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with connect() as conn:
        eng = engagement(conn, args.engagement)
        destination = evidence_dir() / str(eng["id"]) / f"{digest}_{source.name}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
        conn.execute("INSERT INTO evidence(engagement_id,original_name,stored_path,sha256,size,created_at) VALUES(?,?,?,?,?,?)", (eng["id"], source.name, str(destination), digest, source.stat().st_size, now()))
        audit(conn, "evidence.added", {"name": source.name, "sha256": digest}, eng["id"])
    print(f"Evidence stored: {digest}")


def run_tool(args) -> None:
    host = normalize_target(args.target)
    if args.profile is None:
        profiles = REGISTRY[args.tool].profiles
        args.profile = next(name for name in ("safe", "passive", "default") if name in profiles)
    with connect() as conn:
        eng = engagement(conn, args.engagement)
        scopes = conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eng["id"],)).fetchall()
        if not target_allowed(host, scopes):
            audit(conn, "scope.denied", {"target": host, "tool": args.tool}, eng["id"])
            raise SystemExit(f"Denied: {host} is outside engagement scope")
        try:
            spec, command = command_for(args.tool, args.profile, host)
        except (ValueError, RuntimeError) as exc:
            raise SystemExit(str(exc)) from exc
        decision = execution_decision(eng, active=spec.active, approved=args.approve_active)
        if not decision.allowed:
            raise SystemExit(f"Denied: {decision.reason}")
        cur = conn.execute(
            "INSERT INTO tool_runs(engagement_id,tool,profile,target,command,status,started_at) VALUES(?,?,?,?,?,'running',?)",
            (eng["id"], args.tool, args.profile, host, " ".join(command[1:]), now()),
        )
        run_id = cur.lastrowid
        audit(conn, "tool.started", {"run_id": run_id, "tool": args.tool, "profile": args.profile, "target": host}, eng["id"])
    try:
        result = execute(args.tool, args.profile, host, run_id, args.timeout)
        status = "completed" if result["exit_code"] == 0 else "failed"
    except subprocess.TimeoutExpired as exc:
        result = {"error": f"Timed out after {args.timeout}s"}
        status = "timeout"
    with connect() as conn:
        eng = engagement(conn, args.engagement)
        counts = {"entities": 0, "findings": 0}
        if result.get("stdout_path"):
            counts = persist_normalized(conn, eng["id"], args.tool, host, normalize(args.tool, result["stdout_path"], host), now())
        conn.execute(
            "UPDATE tool_runs SET status=?,exit_code=?,stdout_path=?,stderr_path=?,finished_at=? WHERE id=?",
            (status, result.get("exit_code"), result.get("stdout_path"), result.get("stderr_path"), now(), run_id),
        )
        audit(conn, "tool.finished", {"run_id": run_id, "status": status, "normalized": counts}, eng["id"])
        result["normalized"] = counts
    print(json.dumps(result, indent=2))


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.command == "init":
        print(f"Initialized {initialize()}")
    elif args.command == "engagement" and args.engagement_command == "create":
        create_engagement(args)
    elif args.command == "engagement" and args.engagement_command == "list":
        with connect() as conn:
            for row in conn.execute("SELECT name,active_enabled,lab_mode,kill_switch,max_rate,created_at FROM engagements ORDER BY name"):
                print(f"{row['name']}  active={'yes' if row['active_enabled'] else 'no'}  lab={'yes' if row['lab_mode'] else 'no'}  killed={'yes' if row['kill_switch'] else 'no'}  rate={row['max_rate']}")
    elif args.command == "engagement":
        enabled = int(args.engagement_command == "kill")
        with connect() as conn:
            eng = engagement(conn, args.name)
            conn.execute("UPDATE engagements SET kill_switch=? WHERE id=?", (enabled, eng["id"]))
            audit(conn, "engagement.kill_switch", {"enabled": bool(enabled)}, eng["id"])
        print(f"Kill switch {'enabled' if enabled else 'cleared'} for {args.name}")
    elif args.command == "recon":
        run_recon(args)
    elif args.command == "evidence":
        add_evidence(args)
    elif args.command == "report":
        json_path, html_path = build_report(args.engagement)
        print(json_path) ; print(html_path)
    elif args.command == "tools" and args.tools_command == "list":
        print(json.dumps(inventory(), indent=2))
    elif args.command == "tools":
        run_tool(args)
    elif args.command == "workflow" and args.workflow_command == "profiles":
        print(json.dumps({name: [{"tool": s.tool, "profile": s.profile} for s in steps] for name, steps in PROFILES.items()}, indent=2))
    elif args.command == "workflow" and args.workflow_command == "create":
        try:
            print(create_workflow(args.engagement, args.target, args.profile))
        except (ValueError, PermissionError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "workflow":
        try:
            print(json.dumps(run_workflow(args.workflow_id, approve_active=args.approve_active, dry_run=args.dry_run), indent=2))
        except (ValueError, PermissionError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "intel" and args.intel_command == "score":
        print(json.dumps(score_engagement(args.engagement), indent=2))
    elif args.command == "intel":
        print(json.dumps(attack_paths(args.engagement, args.source, max(1, min(args.max_depth, 10))), indent=2))
    elif args.command == "jobs" and args.jobs_command == "enqueue":
        try:
            print(enqueue_workflow(args.engagement, args.workflow_id, args.approve_active))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "jobs" and args.jobs_command == "list":
        print(json.dumps(list_jobs(args.engagement), indent=2))
    elif args.command == "jobs":
        try:
            print(json.dumps(run_next(args.engagement), indent=2))
        except PermissionError as exc:
            raise SystemExit(str(exc)) from exc
    return 0
