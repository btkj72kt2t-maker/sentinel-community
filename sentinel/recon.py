from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone


def passive_recon(host: str) -> dict:
    result = {"target": host, "addresses": [], "tls": None, "errors": []}
    try:
        records = socket.getaddrinfo(host, None)
        result["addresses"] = sorted({r[4][0] for r in records})
    except OSError as exc:
        result["errors"].append(f"DNS: {exc}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                result["tls"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "sans": cert.get("subjectAltName", [])[:100],
                }
    except OSError as exc:
        result["errors"].append(f"TLS: {exc}")
    return result


def nmap_recon(host: str) -> dict:
    binary = shutil.which("nmap")
    if not binary:
        raise RuntimeError("nmap is not installed")
    command = [binary, "-sT", "-sV", "--top-ports", "100", "--max-rate", "50", "-oX", "-", "--", host]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    return {
        "target": host,
        "command": command[1:-2] + [host],
        "exit_code": completed.returncode,
        "xml": completed.stdout,
        "stderr": completed.stderr[-4000:],
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }

