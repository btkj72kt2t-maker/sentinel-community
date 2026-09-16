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
from .extensions import install_manifest, list_extensions
from .health import check_health, evidence_inventory
from .proxy_analysis import analyze_har
from .benchmark import run_benchmarks
from .credential_audit import audit_path
from .lab_validation import validate_marker
from .catalog import capability_catalog
from .daemon import daemon_status, request_stop, run_daemon
from .research import ENGINES, campaign_plan, create_campaign, triage_crash
from .corpus import corpus_stats, ingest_corpus
from .coverage import coverage_trend, import_coverage
from .novelty import add_known_signature, record_reproduction, score_candidate
from .sandbox import sandbox_plan
from .taxonomy import coverage_matrix
from .hunt import HUNT_MODES, run_hunt


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
    ev.add_argument("--classification", choices=["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"], default="CONFIDENTIAL")
    ev.add_argument("--category", default="evidence")
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
    health = sub.add_parser("health")
    health.add_argument("engagement")
    health.add_argument("--repair", action="store_true")
    secure = sub.add_parser("secure")
    ss = secure.add_subparsers(dest="secure_command", required=True)
    sl = ss.add_parser("list")
    sl.add_argument("engagement")
    sv = ss.add_parser("verify")
    sv.add_argument("engagement")
    proxy = sub.add_parser("proxy")
    ps = proxy.add_subparsers(dest="proxy_command", required=True)
    ph = ps.add_parser("analyze-har")
    ph.add_argument("engagement")
    ph.add_argument("file", type=Path)
    extensions = sub.add_parser("extensions")
    xs = extensions.add_subparsers(dest="extensions_command", required=True)
    xs.add_parser("list")
    xi = xs.add_parser("install")
    xi.add_argument("manifest", type=Path)
    lab = sub.add_parser("lab")
    ls = lab.add_subparsers(dest="lab_command", required=True)
    marker = ls.add_parser("validate-marker")
    marker.add_argument("engagement")
    marker.add_argument("url")
    marker.add_argument("--approve-active", action="store_true")
    credentials = sub.add_parser("credentials")
    cs = credentials.add_subparsers(dest="credentials_command", required=True)
    ca = cs.add_parser("audit")
    ca.add_argument("path", type=Path)
    ca.add_argument("--max-files", type=int, default=5000)
    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("--iterations", type=int, default=100)
    daemon = sub.add_parser("daemon")
    ds = daemon.add_subparsers(dest="daemon_command", required=True)
    dr = ds.add_parser("run")
    dr.add_argument("engagement")
    dr.add_argument("--poll-seconds", type=int, default=15)
    dr.add_argument("--max-jobs", type=int, default=100)
    dr.add_argument("--max-runtime", type=int, default=86400)
    dst = ds.add_parser("status")
    dst.add_argument("engagement")
    dsp = ds.add_parser("stop")
    dsp.add_argument("engagement")
    research = sub.add_parser("research")
    rs = research.add_subparsers(dest="research_command", required=True)
    rc = rs.add_parser("create")
    rc.add_argument("engagement")
    rc.add_argument("name")
    rc.add_argument("engine", choices=sorted(ENGINES))
    rc.add_argument("target", type=Path)
    rc.add_argument("corpus", type=Path)
    rc.add_argument("--max-seconds", type=int, default=3600)
    rp = rs.add_parser("plan")
    rp.add_argument("campaign_id", type=int)
    rt = rs.add_parser("triage")
    rt.add_argument("campaign_id", type=int)
    rt.add_argument("log", type=Path)
    ri = rs.add_parser("ingest-corpus")
    ri.add_argument("campaign_id", type=int)
    ri.add_argument("source", type=Path)
    rcs = rs.add_parser("corpus-stats")
    rcs.add_argument("campaign_id", type=int)
    ric = rs.add_parser("import-coverage")
    ric.add_argument("campaign_id", type=int)
    ric.add_argument("telemetry", type=Path)
    rct = rs.add_parser("coverage-trend")
    rct.add_argument("campaign_id", type=int)
    rsb = rs.add_parser("sandbox-plan")
    rsb.add_argument("campaign_id", type=int)
    rr = rs.add_parser("record-reproduction")
    rr.add_argument("crash_id", type=int)
    rr.add_argument("input", type=Path)
    rr.add_argument("outcome", choices=["reproduced", "not_reproduced", "timeout"])
    rr.add_argument("--sanitizer")
    rsc = rs.add_parser("score-candidate")
    rsc.add_argument("crash_id", type=int)
    rks = rs.add_parser("add-known-signature")
    rks.add_argument("fingerprint")
    rks.add_argument("reference")
    rks.add_argument("--source", default="manual")
    sub.add_parser("catalog")
    sub.add_parser("coverage")
    hunt = sub.add_parser("hunt", help="Run a scope-bound assessment and produce a report")
    hunt.add_argument("engagement")
    hunt.add_argument("target")
    hunt.add_argument("--mode", choices=sorted(HUNT_MODES), default="full-safe")
    hunt.add_argument("--approve-active", action="store_true")
    hunt.add_argument("--dry-run", action="store_true")
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
        conn.execute("INSERT INTO evidence(engagement_id,original_name,stored_path,sha256,size,created_at,classification,category) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], source.name, str(destination), digest, source.stat().st_size, now(), args.classification, args.category))
        audit(conn, "evidence.added", {"name": source.name, "sha256": digest, "classification": args.classification, "category": args.category}, eng["id"])
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
    elif args.command == "health":
        print(json.dumps(check_health(args.engagement, args.repair), indent=2))
    elif args.command == "secure" and args.secure_command == "list":
        print(json.dumps(evidence_inventory(args.engagement), indent=2))
    elif args.command == "secure":
        print(json.dumps(check_health(args.engagement, False), indent=2))
    elif args.command == "proxy":
        try:
            print(json.dumps(analyze_har(args.engagement, args.file), indent=2))
        except (ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "extensions" and args.extensions_command == "list":
        print(json.dumps(list_extensions(), indent=2))
    elif args.command == "extensions":
        try:
            print(json.dumps(install_manifest(args.manifest), indent=2))
        except (ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "lab":
        try:
            print(json.dumps(validate_marker(args.engagement, args.url, args.approve_active), indent=2))
        except (ValueError, PermissionError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "credentials":
        try:
            print(json.dumps(audit_path(args.path, max(1, min(args.max_files, 50000))), indent=2))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "benchmark":
        print(json.dumps(run_benchmarks(args.iterations), indent=2))
    elif args.command == "daemon" and args.daemon_command == "run":
        try:
            print(json.dumps(run_daemon(args.engagement, args.poll_seconds, args.max_jobs, args.max_runtime), indent=2))
        except PermissionError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "daemon" and args.daemon_command == "status":
        print(json.dumps(daemon_status(args.engagement), indent=2))
    elif args.command == "daemon":
        print(request_stop(args.engagement))
    elif args.command == "research" and args.research_command == "create":
        try:
            print(create_campaign(args.engagement, args.name, args.engine, args.target, args.corpus, args.max_seconds))
        except (ValueError, PermissionError) as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "research" and args.research_command == "plan":
        try:
            print(json.dumps(campaign_plan(args.campaign_id), indent=2))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "research" and args.research_command == "triage":
        try:
            print(json.dumps(triage_crash(args.campaign_id, args.log), indent=2))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    elif args.command == "research" and args.research_command == "ingest-corpus":
        print(json.dumps(ingest_corpus(args.campaign_id, args.source), indent=2))
    elif args.command == "research" and args.research_command == "corpus-stats":
        print(json.dumps(corpus_stats(args.campaign_id), indent=2))
    elif args.command == "research" and args.research_command == "import-coverage":
        print(json.dumps(import_coverage(args.campaign_id, args.telemetry), indent=2))
    elif args.command == "research" and args.research_command == "coverage-trend":
        print(json.dumps(coverage_trend(args.campaign_id), indent=2))
    elif args.command == "research" and args.research_command == "sandbox-plan":
        print(json.dumps(sandbox_plan(args.campaign_id), indent=2))
    elif args.command == "research" and args.research_command == "record-reproduction":
        print(record_reproduction(args.crash_id, args.input, args.outcome, args.sanitizer))
    elif args.command == "research" and args.research_command == "score-candidate":
        print(json.dumps(score_candidate(args.crash_id), indent=2))
    elif args.command == "research":
        add_known_signature(args.fingerprint, args.reference, args.source)
        print("Known signature recorded")
    elif args.command == "catalog":
        print(json.dumps(capability_catalog(), indent=2))
    elif args.command == "coverage":
        print(json.dumps(coverage_matrix(), indent=2))
    elif args.command == "hunt":
        try:
            print(json.dumps(run_hunt(args.engagement, args.target, args.mode, approve_active=args.approve_active, dry_run=args.dry_run), indent=2))
        except (ValueError, PermissionError) as exc:
            raise SystemExit(str(exc)) from exc
    return 0
