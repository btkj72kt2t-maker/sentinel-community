from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path

from .db import audit, connect, engagement


SIGNATURES = {
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "ZIP archive",
    b"hsqs": "SquashFS filesystem",
    b"sqsh": "SquashFS filesystem",
    b"\x1f\x8b\x08": "gzip stream",
    b"ustar": "TAR archive",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_artifact(engagement_name: str, path: Path, max_bytes: int = 64 * 1024 * 1024) -> dict:
    path = path.resolve()
    if not path.is_file():
        raise ValueError("artifact must be an existing local file")
    size = path.stat().st_size
    limit = max(4096, min(max_bytes, 256 * 1024 * 1024))
    with path.open("rb") as handle:
        data = handle.read(limit)
    hits = []
    for signature, label in SIGNATURES.items():
        start = 0
        while len(hits) < 256:
            offset = data.find(signature, start)
            if offset < 0:
                break
            hits.append({"type": label, "offset": offset})
            start = offset + 1
    result = {
        "file": path.name,
        "size": size,
        "sha256": _sha256(path),
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "bytes_analyzed": len(data),
        "truncated": size > len(data),
        "entropy": round(_entropy(data), 4),
        "embedded_signatures": hits,
        "extraction_performed": False,
        "execution_performed": False,
    }
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        audit(conn, "artifact.inspected", {key: result[key] for key in ("file", "size", "sample_sha256", "bytes_analyzed", "truncated", "entropy")}, eng["id"])
    return result
