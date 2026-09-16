from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .db import audit, connect, now

ALLOWED_CATEGORIES = {"recon", "web", "network", "tls", "reporting", "forensics", "osint"}
REQUIRED_FIELDS = {"name", "version", "category", "description"}


def install_manifest(path: Path) -> dict:
    path = path.resolve()
    if not path.is_file() or path.name != "sentinel-extension.json":
        raise ValueError("expected a sentinel-extension.json manifest")
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        raise ValueError("extension manifest is too large")
    manifest = json.loads(raw)
    missing = REQUIRED_FIELDS - set(manifest)
    if missing:
        raise ValueError(f"missing manifest fields: {', '.join(sorted(missing))}")
    if manifest["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("unsupported extension category")
    if not str(manifest["name"]).replace("-", "").replace("_", "").isalnum():
        raise ValueError("invalid extension name")
    digest = hashlib.sha256(raw).hexdigest()
    with connect() as conn:
        conn.execute(
            "INSERT INTO extensions(name,version,category,manifest_path,sha256,enabled,installed_at) VALUES(?,?,?,?,?,0,?) "
            "ON CONFLICT(name) DO UPDATE SET version=excluded.version,category=excluded.category,manifest_path=excluded.manifest_path,sha256=excluded.sha256,enabled=0,installed_at=excluded.installed_at",
            (manifest["name"], manifest["version"], manifest["category"], str(path), digest, now()),
        )
        audit(conn, "extension.registered", {"name": manifest["name"], "version": manifest["version"], "sha256": digest})
    return {"manifest": manifest, "sha256": digest, "enabled": False, "note": "Registration does not execute extension code"}


def list_extensions() -> list[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM extensions ORDER BY name")]

