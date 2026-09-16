from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .config import data_dir
from .db import audit, connect, now


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ingest_corpus(campaign_id: int, source: Path, max_files: int = 10000, max_size: int = 16 * 1024 * 1024) -> dict:
    source = source.resolve()
    if not source.exists():
        raise ValueError("corpus source does not exist")
    candidates = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
    stored, duplicates, skipped = 0, 0, 0
    with connect() as conn:
        campaign = conn.execute("SELECT * FROM research_campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not campaign:
            raise ValueError("unknown campaign")
        destination = data_dir() / "corpora" / str(campaign_id)
        destination.mkdir(parents=True, exist_ok=True)
        for path in candidates[:max_files]:
            size = path.stat().st_size
            if size > max_size:
                skipped += 1
                continue
            digest = _sha256(path)
            target = destination / digest
            exists = conn.execute("SELECT 1 FROM corpus_entries WHERE campaign_id=? AND sha256=?", (campaign_id, digest)).fetchone()
            if exists:
                duplicates += 1
                continue
            shutil.copy2(path, target)
            conn.execute("INSERT INTO corpus_entries(campaign_id,sha256,source_path,stored_path,size,created_at) VALUES(?,?,?,?,?,?)", (campaign_id, digest, str(path), str(target), size, now()))
            stored += 1
        audit(conn, "research.corpus_ingested", {"campaign_id": campaign_id, "stored": stored, "duplicates": duplicates, "skipped": skipped}, campaign["engagement_id"])
    return {"campaign_id": campaign_id, "stored": stored, "duplicates": duplicates, "skipped": skipped}


def corpus_stats(campaign_id: int) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT COUNT(*) count,COALESCE(SUM(size),0) bytes,COALESCE(MAX(size),0) largest FROM corpus_entries WHERE campaign_id=?", (campaign_id,)).fetchone()
        if not conn.execute("SELECT 1 FROM research_campaigns WHERE id=?", (campaign_id,)).fetchone():
            raise ValueError("unknown campaign")
        return {"campaign_id": campaign_id, **dict(row)}

