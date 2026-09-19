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
    lab_only: bool = False
    homepage: str = ""
    output_format: str = "text"
    capabilities: tuple[str, ...] = ()


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


def _naabu(target: str) -> list[str]:
    return ["naabu", "-host", target, "-top-ports", "100", "-rate", "25", "-json", "-silent"]


def _katana(target: str) -> list[str]:
    return ["katana", "-u", f"https://{target}", "-depth", "2", "-jsonl", "-host-rate-limit", "10", "-concurrency", "2", "-parallelism", "1", "-silent"]


def _feroxbuster(target: str) -> list[str]:
    return ["feroxbuster", "--url", f"https://{target}", "--depth", "1", "--rate-limit", "10", "--threads", "2", "--json", "--silent", "--no-state"]


def _dnsx(target: str) -> list[str]:
    return ["dnsx", "-u", target, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp", "-j", "-rl", "25", "-silent", "-duc"]


def _tlsx(target: str) -> list[str]:
    return ["tlsx", "-u", target, "-p", "443", "-san", "-cn", "-so", "-tls-version", "-cipher", "-hash", "sha256", "-probe-status", "-expired", "-self-signed", "-mismatched", "-untrusted", "-verify-cert", "-c", "2", "-delay", "200ms", "-timeout", "5", "-retry", "1", "-j", "-silent", "-duc"]


REGISTRY: dict[str, ToolSpec] = {
    "dig": ToolSpec("dig", "recon", "DNS record collection", False, {"default": _dig}),
    "whois": ToolSpec("whois", "recon", "Registration metadata", False, {"default": _whois}),
    "subfinder": ToolSpec("subfinder", "recon", "Passive subdomain discovery", False, {"passive": _subfinder}),
    "httpx": ToolSpec("httpx", "web", "HTTP service and technology probing", True, {"safe": _httpx}),
    "whatweb": ToolSpec("whatweb", "web", "Web technology fingerprinting", True, {"safe": _whatweb}),
    "testssl.sh": ToolSpec("testssl.sh", "tls", "TLS configuration assessment", True, {"safe": _testssl}),
    "nmap": ToolSpec("nmap", "network", "Rate-limited service discovery", True, {"safe": _nmap}),
    "nuclei": ToolSpec("nuclei", "vulnerability", "Template-based security checks", True, {"safe": _nuclei}),
    "naabu": ToolSpec("naabu", "enumeration", "Rate-limited top-port enumeration", True, {"safe": _naabu}),
    "katana": ToolSpec("katana", "enumeration", "Bounded web endpoint crawling", True, {"safe": _katana}),
    "feroxbuster": ToolSpec("feroxbuster", "enumeration", "Bounded web content discovery", True, {"safe": _feroxbuster}),
    "dnsx": ToolSpec("dnsx", "dns", "Bounded multi-record DNS validation", True, {"safe": _dnsx}, homepage="https://github.com/projectdiscovery/dnsx", output_format="jsonl", capabilities=("dns-validation", "asset-correlation")),
    "tlsx": ToolSpec("tlsx", "tls", "Bounded TLS certificate and configuration collection", True, {"safe": _tlsx}, homepage="https://github.com/projectdiscovery/tlsx", output_format="jsonl", capabilities=("certificate-inventory", "tls-misconfiguration")),
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
            "homepage": spec.homepage,
            "output_format": spec.output_format,
            "capabilities": list(spec.capabilities),
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
