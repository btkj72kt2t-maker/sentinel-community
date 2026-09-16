from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .db import audit, connect, engagement, now

ENGINES = {"afl++", "libfuzzer", "honggfuzz", "jazzer"}


def create_campaign(engagement_name: str, name: str, engine: str, target: Path, corpus: Path, max_seconds: int = 3600) -> int:
    if engine not in ENGINES:
        raise ValueError(f"unsupported fuzzing engine: {engine}")
    target, corpus = target.resolve(), corpus.resolve()
    if not target.is_file():
        raise ValueError("target must be an existing local file")
    if not corpus.is_dir():
        raise ValueError("corpus must be an existing local directory")
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        if not eng["lab_mode"]:
            raise PermissionError("fuzzing campaigns require an isolated lab engagement")
        cur = conn.execute(
            "INSERT INTO research_campaigns(engagement_id,name,engine,target_path,corpus_path,max_seconds,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (eng["id"], name, engine, str(target), str(corpus), max(60, min(max_seconds, 7 * 86400)), now(), now()),
        )
        audit(conn, "research.campaign_created", {"campaign_id": cur.lastrowid, "name": name, "engine": engine}, eng["id"])
        return cur.lastrowid


def campaign_plan(campaign_id: int) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT * FROM research_campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not row:
            raise ValueError("unknown campaign")
        return {"campaign": dict(row), "requirements": {"afl++": ["afl-fuzz"], "libfuzzer": ["clang", "sanitizer-instrumented target"], "honggfuzz": ["honggfuzz"], "jazzer": ["jazzer"]}[row["engine"]], "execution": "Manual or future sandbox worker; no shell command is generated"}


def triage_crash(campaign_id: int, log_path: Path) -> dict:
    log_path = log_path.resolve()
    if not log_path.is_file():
        raise ValueError("crash log does not exist")
    text = log_path.read_text(encoding="utf-8", errors="replace")[:2_000_000]
    crash_type = "unknown"
    for label, pattern in (
        ("heap-buffer-overflow", r"heap-buffer-overflow"),
        ("stack-buffer-overflow", r"stack-buffer-overflow"),
        ("use-after-free", r"use-after-free"),
        ("undefined-behavior", r"runtime error:"),
        ("segmentation-fault", r"(?:SEGV|segmentation fault)"),
    ):
        if re.search(pattern, text, re.IGNORECASE):
            crash_type = label
            break
    frames = re.findall(r"#\d+\s+[^\n]+", text)[:8]
    signature = crash_type + "\n" + "\n".join(re.sub(r"0x[0-9a-f]+", "0xADDR", f, flags=re.I) for f in frames)
    fingerprint = hashlib.sha256(signature.encode()).hexdigest()
    summary = frames[0][:500] if frames else text.splitlines()[0][:500] if text.splitlines() else "Empty crash log"
    with connect() as conn:
        campaign = conn.execute("SELECT * FROM research_campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not campaign:
            raise ValueError("unknown campaign")
        conn.execute(
            "INSERT INTO crashes(campaign_id,fingerprint,crash_type,summary,log_path,created_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(campaign_id,fingerprint) DO UPDATE SET occurrences=crashes.occurrences+1,log_path=excluded.log_path",
            (campaign_id, fingerprint, crash_type, summary, str(log_path), now()),
        )
        audit(conn, "research.crash_triaged", {"campaign_id": campaign_id, "fingerprint": fingerprint, "crash_type": crash_type}, campaign["engagement_id"])
    return {"campaign_id": campaign_id, "fingerprint": fingerprint, "crash_type": crash_type, "summary": summary, "frames": frames}

