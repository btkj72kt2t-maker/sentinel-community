from __future__ import annotations

import hashlib
from pathlib import Path

from .tools import inventory


def executable_manifest() -> dict:
    entries = []
    for item in inventory():
        if not item["installed"]:
            continue
        path = Path(item["path"]).resolve()
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            digest = None
        entries.append({"name": item["name"], "path": str(path), "sha256": digest, "verified": digest is not None})
    return {"executables": entries, "policy": "Pin expected hashes in deployment configuration and review every change before execution."}
