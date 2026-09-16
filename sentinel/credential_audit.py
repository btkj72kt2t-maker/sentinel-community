from __future__ import annotations

import hashlib
import re
from pathlib import Path

PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[ps]_[A-Za-z0-9]{30,}\b"),
    "generic_secret": re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?([^\s'\"]{8,})"),
}


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def audit_path(path: Path, max_files: int = 5000, max_file_size: int = 2 * 1024 * 1024) -> dict:
    path = path.resolve()
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")
    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    findings, scanned, skipped = [], 0, 0
    for file_path in files[:max_files]:
        try:
            if file_path.stat().st_size > max_file_size:
                skipped += 1
                continue
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        scanned += 1
        for line_number, line in enumerate(text.splitlines(), 1):
            for kind, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match:
                    matched = match.group(0)
                    findings.append({"type": kind, "path": str(file_path), "line": line_number, "fingerprint": _fingerprint(matched), "value": "[REDACTED]"})
    return {"root": str(path), "files_scanned": scanned, "files_skipped": skipped, "findings": findings}

