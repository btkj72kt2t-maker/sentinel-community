from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import data_dir


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    description: str
    active: bool
    profiles: dict[str, Callable[[str], list[str]]]


def _nmap(target: str) -> list[str]:
    return ["nmap", "-sT", "-sV", "--top-ports", "100", "--max-rate", "50", "-oX", "-", "--", target]


def _nuclei(target: str) -> list[str]:
    return ["nuclei", "-u", target, "-severity", "info,low,medium,high,critical", "-rate-limit", "25", "-jsonl"]


def _subfinder(target: str) -> list[str]:
    return ["subfinder", "-d", target, "-silent", "-json"]


def _httpx(target: str) -> list[str]:
    return ["httpx", "-u", target, "-status-code", "-title", "-tech-detect", "-json", "-rate-limit", "25"]


def _whatweb(target: str) -> list[str]:
    return ["whatweb", "--log-json=-", "--aggression", "1", target]


def _testssl(target: str) -> list[str]:
    return ["testssl.sh", "--quiet", "--jsonfile-pretty", "/dev/stdout", target]


def _whois(target: str) -> list[str]:
    return ["whois", target]


def _dig(target: str) -> list[str]:
    return ["dig", "+noall", "+answer", target, "A", target, "AAAA", target, "MX", target, "TXT"]


REGISTRY: dict[str, ToolSpec] = {
    "dig": ToolSpec("dig", "recon", "DNS record collection", False, {"default": _dig}),
    "whois": ToolSpec("whois", "recon", "Registration metadata", False, {"default": _whois}),
    "subfinder": ToolSpec("subfinder", "recon", "Passive subdomain discovery", False, {"passive": _subfinder}),
    "httpx": ToolSpec("httpx", "web", "HTTP service and technology probing", True, {"safe": _httpx}),
    "whatweb": ToolSpec("whatweb", "web", "Web technology fingerprinting", True, {"safe": _whatweb}),
    "testssl.sh": ToolSpec("testssl.sh", "tls", "TLS configuration assessment", True, {"safe": _testssl}),
    "nmap": ToolSpec("nmap", "network", "Rate-limited service discovery", True, {"safe": _nmap}),
    "nuclei": ToolSpec("nuclei", "vulnerability", "Template-based security checks", True, {"safe": _nuclei}),
}


def inventory() -> list[dict]:
    output = []
    for spec in REGISTRY.values():
        path = shutil.which(spec.name)
        output.append({
            "name": spec.name,
            "category": spec.category,
            "description": spec.description,
            "active": spec.active,
            "installed": bool(path),
            "path": path,
            "profiles": sorted(spec.profiles),
        })
    return output


def command_for(tool: str, profile: str, target: str) -> tuple[ToolSpec, list[str]]:
    if tool not in REGISTRY:
        raise ValueError(f"Unknown tool adapter: {tool}")
    spec = REGISTRY[tool]
    if profile not in spec.profiles:
        raise ValueError(f"Unknown {tool} profile: {profile}")
    command = spec.profiles[profile](target)
    binary = shutil.which(command[0])
    if not binary:
        raise RuntimeError(f"{command[0]} is not installed")
    command[0] = binary
    return spec, command


def execute(tool: str, profile: str, target: str, run_id: int, timeout: int = 600) -> dict:
    spec, command = command_for(tool, profile, target)
    run_dir = data_dir() / "runs" / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    stdout_path = run_dir / "stdout.txt"
    stderr_path = run_dir / "stderr.txt"
    stdout_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(completed.stderr, encoding="utf-8", errors="replace")
    return {
        "tool": spec.name,
        "profile": profile,
        "target": target,
        "command": shlex.join(command[1:]),
        "exit_code": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_preview": completed.stdout[:4000],
        "stderr_preview": completed.stderr[:2000],
    }

