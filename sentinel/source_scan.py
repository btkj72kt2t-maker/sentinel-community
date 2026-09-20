from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from .config import data_dir
from .db import audit, connect, engagement, now
from .supply_chain import import_cyclonedx


TOOLS = ("gitleaks", "osv-scanner", "semgrep", "syft", "trivy")
SEVERITIES = {"UNKNOWN": "info", "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def _command(tool: str, source: Path) -> list[str]:
    path = str(source)
    commands = {
        "osv-scanner": ["osv-scanner", "scan", "source", "--recursive", "--allow-no-lockfiles", "--format", "json", "--verbosity", "error", "--experimental-exclude", ".git", "--experimental-exclude", ".sentinel", path],
        "semgrep": ["semgrep", "scan", "--config", str(Path(__file__).with_name("data") / "semgrep-rules.yml"), "--json", "--metrics", "off", "--disable-version-check", "--max-target-bytes", "1000000", "--exclude", ".git", "--exclude", ".sentinel", path],
        "trivy": ["trivy", "filesystem", "--format", "json", "--scanners", "vuln,misconfig,secret", "--detection-priority", "precise", "--disable-telemetry", "--skip-version-check", "--no-progress", "--skip-dirs", ".git", "--skip-dirs", ".sentinel", path],
        "gitleaks": ["gitleaks", "dir", "--report-format", "json", "--report-path", "-", "--redact=100", "--no-banner", "--no-color", "--max-archive-depth", "0", "--max-target-megabytes", "50", "--timeout", "300", path],
        "syft": ["syft", "scan", f"dir:{path}", "--output", "cyclonedx-json", "--exclude", "**/.git/**", "--exclude", "**/.sentinel/**", "--parallelism", "2", "--quiet"],
    }
    return commands[tool]


def _clean_details(item: dict) -> dict:
    blocked = {"secret", "match", "line", "code", "content"}
    return {key: value for key, value in item.items() if key.lower() not in blocked}


def _findings(tool: str, payload: object) -> list[dict]:
    findings: list[dict] = []
    if tool == "osv-scanner" and isinstance(payload, dict):
        for result in payload.get("results", []):
            source = result.get("source", {})
            for package in result.get("packages", []):
                identity = package.get("package", {})
                name = identity.get("name", "unknown-package")
                version = identity.get("version", "unknown-version")
                for vulnerability in package.get("vulnerabilities", []):
                    vuln_id = vulnerability.get("id", "OSV finding")
                    findings.append({"severity": "medium", "title": f"{vuln_id} in {name}@{version}", "details": {"id": vuln_id, "aliases": vulnerability.get("aliases", []), "package": identity, "source": source}})
    elif tool == "trivy" and isinstance(payload, dict):
        for result in payload.get("Results", []):
            target = result.get("Target", "source")
            for item in result.get("Vulnerabilities") or []:
                vuln_id = item.get("VulnerabilityID", "Dependency vulnerability")
                package = item.get("PkgName", "unknown-package")
                findings.append({"severity": SEVERITIES.get(str(item.get("Severity", "UNKNOWN")).upper(), "info"), "title": f"{vuln_id} in {package}", "details": _clean_details({**item, "Target": target})})
            for item in result.get("Misconfigurations") or []:
                findings.append({"severity": SEVERITIES.get(str(item.get("Severity", "UNKNOWN")).upper(), "info"), "title": str(item.get("Title") or item.get("ID") or "Configuration finding"), "details": _clean_details({**item, "Target": target})})
            for item in result.get("Secrets") or []:
                findings.append({"severity": SEVERITIES.get(str(item.get("Severity", "HIGH")).upper(), "high"), "title": str(item.get("Title") or item.get("RuleID") or "Potential secret exposure"), "details": {"RuleID": item.get("RuleID"), "Category": item.get("Category"), "Severity": item.get("Severity"), "Target": target, "StartLine": item.get("StartLine"), "EndLine": item.get("EndLine"), "redacted": True}})
    elif tool == "gitleaks" and isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            findings.append({"severity": "high", "title": str(item.get("Description") or item.get("RuleID") or "Potential secret exposure"), "details": {"RuleID": item.get("RuleID"), "File": item.get("File"), "StartLine": item.get("StartLine"), "EndLine": item.get("EndLine"), "Fingerprint": item.get("Fingerprint"), "redacted": True}})
    elif tool == "semgrep" and isinstance(payload, dict):
        severity_map = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}
        for item in payload.get("results", []):
            extra = item.get("extra") or {}
            findings.append({"severity": severity_map.get(str(extra.get("severity", "INFO")).upper(), "info"), "title": str(extra.get("message") or item.get("check_id") or "Static analysis finding"), "details": {"check_id": item.get("check_id"), "path": item.get("path"), "start": (item.get("start") or {}).get("line"), "end": (item.get("end") or {}).get("line"), "severity": extra.get("severity"), "metadata": extra.get("metadata") or {}, "source_code_stored": False}})
    return findings


def scan_source(name: str, tool: str, source: Path, *, timeout: int = 600) -> dict:
    if tool not in TOOLS:
        raise ValueError("unsupported source scanner")
    source = source.resolve()
    if not source.exists():
        raise ValueError("source path does not exist")
    state = data_dir()
    if source == state or state in source.parents:
        raise PermissionError("the Sentinel data directory cannot be scanned as source")
    binary = shutil.which(tool)
    if not binary:
        raise RuntimeError(f"{tool} is not installed")
    command = _command(tool, source)
    command[0] = binary
    run_cwd = None
    if tool == "osv-scanner" and source.is_dir():
        # OSV's Go path handling can lose a trailing space in an absolute
        # directory name.  Running from the source root also keeps its output
        # portable while preserving the fixed, non-shell argument vector.
        command[-1] = "."
        run_cwd = str(source)
    with connect() as conn:
        eng = engagement(conn, name)
        cur = conn.execute("INSERT INTO tool_runs(engagement_id,tool,profile,target,command,status,started_at) VALUES(?,?,?,?,?,'running',?)", (eng["id"], tool, "source-safe", str(source), " ".join(command[1:]), now()))
        run_id = cur.lastrowid
    run_dir = data_dir() / "runs" / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({
        "SEMGREP_SETTINGS_FILE": str(data_dir() / "semgrep-settings.yml"),
        "SEMGREP_LOG_FILE": str(data_dir() / "semgrep.log"),
        "TRIVY_CACHE_DIR": str(data_dir() / "cache" / "trivy"),
    })
    brew_ca = Path("/opt/homebrew/etc/ca-certificates/cert.pem")
    if brew_ca.is_file() and "SSL_CERT_FILE" not in environment:
        environment["SSL_CERT_FILE"] = str(brew_ca)
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=max(30, min(timeout, 3600)), check=False, env=environment, cwd=run_cwd)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        completed = subprocess.CompletedProcess(command, 124, stdout=stdout, stderr=f"{stderr}\nscan timed out")
    stdout_path, stderr_path = run_dir / "stdout.json", run_dir / "stderr.txt"
    stdout_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(completed.stderr, encoding="utf-8", errors="replace")
    accepted_codes = {0, 1} if tool == "gitleaks" else {0}
    status = "completed" if completed.returncode in accepted_codes else "failed"
    parsed: object = {}
    parse_error = None
    try:
        parsed = json.loads(completed.stdout or ("[]" if tool == "gitleaks" else "{}"))
    except json.JSONDecodeError as exc:
        parse_error = str(exc)
        status = "failed"
    normalized = _findings(tool, parsed)
    with connect() as conn:
        eng = engagement(conn, name)
        inserted = 0
        for finding in normalized:
            locator = finding["details"].get("path") or finding["details"].get("File") or finding["details"].get("Target") or ""
            line = finding["details"].get("start") or finding["details"].get("StartLine") or ""
            rule = finding["details"].get("check_id") or finding["details"].get("RuleID") or finding["details"].get("id") or ""
            fingerprint = hashlib.sha256(f"{tool}\0{source}\0{finding['title']}\0{locator}\0{line}\0{rule}".encode()).hexdigest()
            details = json.dumps(finding["details"], sort_keys=True)
            existing = conn.execute("SELECT id FROM findings WHERE engagement_id=? AND fingerprint=?", (eng["id"], fingerprint)).fetchone()
            if existing:
                conn.execute("UPDATE findings SET occurrences=occurrences+1,details=?,severity=? WHERE id=?", (details, finding["severity"], existing["id"]))
            else:
                conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at,fingerprint) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], str(source), tool, finding["severity"], finding["title"], details, now(), fingerprint))
            inserted += 1
        conn.execute("UPDATE tool_runs SET status=?,exit_code=?,stdout_path=?,stderr_path=?,finished_at=? WHERE id=?", (status, completed.returncode, str(stdout_path), str(stderr_path), now(), run_id))
        audit(conn, "source.scan_completed", {"run_id": run_id, "tool": tool, "source": str(source), "status": status, "findings": inserted, "parse_error": parse_error}, eng["id"])
    sbom = None
    if tool == "syft" and status == "completed":
        sbom = import_cyclonedx(name, stdout_path)
    return {"run_id": run_id, "tool": tool, "source": str(source), "status": status, "exit_code": completed.returncode, "findings": len(normalized), "output": str(stdout_path), "sbom": sbom, "parse_error": parse_error, "redaction": "Secret values and matching source lines are not normalized into findings."}
