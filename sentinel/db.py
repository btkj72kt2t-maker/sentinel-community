from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import data_dir, db_path, evidence_dir, reports_dir

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS engagements (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, active_enabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, value TEXT NOT NULL, allow_subdomains INTEGER NOT NULL DEFAULT 0,
 UNIQUE(engagement_id, kind, value)
);
CREATE TABLE IF NOT EXISTS entities (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, value TEXT NOT NULL, risk TEXT NOT NULL DEFAULT 'unknown',
 attributes TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
 UNIQUE(engagement_id, kind, value)
);
CREATE TABLE IF NOT EXISTS relationships (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 source_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 relation TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0, evidence TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL, UNIQUE(engagement_id, source_id, target_id, relation)
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 target TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_runs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 tool TEXT NOT NULL, profile TEXT NOT NULL, target TEXT NOT NULL, command TEXT NOT NULL,
 status TEXT NOT NULL, exit_code INTEGER, stdout_path TEXT, stderr_path TEXT,
 started_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS workflows (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 profile TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
 current_step INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workflow_steps (
 id INTEGER PRIMARY KEY, workflow_id INTEGER NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
 position INTEGER NOT NULL, tool TEXT NOT NULL, profile TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 tool_run_id INTEGER REFERENCES tool_runs(id) ON DELETE SET NULL, message TEXT,
 UNIQUE(workflow_id, position)
);
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0, message TEXT, created_at TEXT NOT NULL,
 started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS schedules (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 target TEXT NOT NULL, profile TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
 approve_active INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
 last_run_at TEXT, next_run_at TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(engagement_id,target,profile)
);
CREATE TABLE IF NOT EXISTS evidence (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 original_name TEXT NOT NULL, stored_path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS extensions (
 id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, version TEXT NOT NULL, category TEXT NOT NULL,
 manifest_path TEXT NOT NULL, sha256 TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
 installed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proxy_observations (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 target TEXT NOT NULL, method TEXT NOT NULL, url TEXT NOT NULL, status INTEGER,
 severity TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
 fingerprint TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(engagement_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS research_campaigns (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 name TEXT NOT NULL, engine TEXT NOT NULL, target_path TEXT NOT NULL, corpus_path TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'planned', max_seconds INTEGER NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(engagement_id, name)
);
CREATE TABLE IF NOT EXISTS crashes (
 id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES research_campaigns(id) ON DELETE CASCADE,
 fingerprint TEXT NOT NULL, crash_type TEXT NOT NULL, summary TEXT NOT NULL,
 log_path TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
 UNIQUE(campaign_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS corpus_entries (
 id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES research_campaigns(id) ON DELETE CASCADE,
 sha256 TEXT NOT NULL, source_path TEXT NOT NULL, stored_path TEXT NOT NULL, size INTEGER NOT NULL,
 coverage_edges INTEGER, created_at TEXT NOT NULL,
 UNIQUE(campaign_id, sha256)
);
CREATE TABLE IF NOT EXISTS coverage_samples (
 id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES research_campaigns(id) ON DELETE CASCADE,
 executions INTEGER NOT NULL, edges INTEGER NOT NULL, paths INTEGER NOT NULL,
 crashes INTEGER NOT NULL, hangs INTEGER NOT NULL, sampled_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reproductions (
 id INTEGER PRIMARY KEY, crash_id INTEGER NOT NULL REFERENCES crashes(id) ON DELETE CASCADE,
 input_sha256 TEXT NOT NULL, outcome TEXT NOT NULL, sanitizer TEXT,
 environment TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_signatures (
 id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, reference TEXT NOT NULL,
 source TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerability_intelligence (
 cve TEXT PRIMARY KEY, kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT,
 ransomware_use TEXT, vendor TEXT, product TEXT, required_action TEXT,
 epss REAL, epss_percentile REAL, epss_date TEXT,
 attributes TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_vulnerabilities (
 finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 cve TEXT NOT NULL REFERENCES vulnerability_intelligence(cve) ON DELETE CASCADE,
 confidence REAL NOT NULL DEFAULT 1.0,
 PRIMARY KEY(finding_id,cve)
);
CREATE TABLE IF NOT EXISTS intelligence_feeds (
 id INTEGER PRIMARY KEY, source TEXT NOT NULL, url TEXT NOT NULL, sha256 TEXT NOT NULL,
 stored_path TEXT NOT NULL, size INTEGER NOT NULL, fetched_at TEXT NOT NULL,
 UNIQUE(source,sha256)
);
CREATE TABLE IF NOT EXISTS stix_objects (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 stix_id TEXT NOT NULL, object_type TEXT NOT NULL, object_json TEXT NOT NULL,
 created_at TEXT NOT NULL, UNIQUE(engagement_id,stix_id)
);
CREATE TABLE IF NOT EXISTS components (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 bom_ref TEXT NOT NULL, name TEXT NOT NULL, version TEXT, purl TEXT, component_type TEXT,
 attributes TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
 UNIQUE(engagement_id,bom_ref)
);
CREATE TABLE IF NOT EXISTS component_vulnerabilities (
 component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
 cve TEXT NOT NULL REFERENCES vulnerability_intelligence(cve) ON DELETE CASCADE,
 vex_status TEXT NOT NULL DEFAULT 'unknown', justification TEXT, response TEXT,
 source TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(component_id,cve,source)
);
CREATE TABLE IF NOT EXISTS validation_proofs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 outcome TEXT NOT NULL, evidence_path TEXT NOT NULL, evidence_sha256 TEXT NOT NULL,
 rollback_verified INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proof_runs (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
 module_id TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
 request_budget INTEGER NOT NULL DEFAULT 0, result TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS callback_tokens (
 id INTEGER PRIMARY KEY, engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
 finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
 token TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS callback_events (
 id INTEGER PRIMARY KEY, token_id INTEGER NOT NULL REFERENCES callback_tokens(id) ON DELETE CASCADE,
 method TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL,
 headers TEXT NOT NULL DEFAULT '{}', observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
 action TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize() -> Path:
    for path in (data_dir(), evidence_dir(), reports_dir()):
        path.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path())) as conn:
        conn.executescript(SCHEMA)
        columns = {r[1] for r in conn.execute("PRAGMA table_info(engagements)")}
        for name, statement in (
            ("lab_mode", "ALTER TABLE engagements ADD COLUMN lab_mode INTEGER NOT NULL DEFAULT 0"),
            ("kill_switch", "ALTER TABLE engagements ADD COLUMN kill_switch INTEGER NOT NULL DEFAULT 0"),
            ("max_rate", "ALTER TABLE engagements ADD COLUMN max_rate INTEGER NOT NULL DEFAULT 25"),
        ):
            if name not in columns:
                conn.execute(statement)
        finding_columns = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        for name, statement in (
            ("fingerprint", "ALTER TABLE findings ADD COLUMN fingerprint TEXT"),
            ("status", "ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open'"),
            ("risk_score", "ALTER TABLE findings ADD COLUMN risk_score REAL NOT NULL DEFAULT 0"),
            ("occurrences", "ALTER TABLE findings ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1"),
        ):
            if name not in finding_columns:
                conn.execute(statement)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings(engagement_id,fingerprint) WHERE fingerprint IS NOT NULL")
        evidence_columns = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
        for name, statement in (
            ("classification", "ALTER TABLE evidence ADD COLUMN classification TEXT NOT NULL DEFAULT 'CONFIDENTIAL'"),
            ("category", "ALTER TABLE evidence ADD COLUMN category TEXT NOT NULL DEFAULT 'evidence'"),
            ("verified_at", "ALTER TABLE evidence ADD COLUMN verified_at TEXT"),
        ):
            if name not in evidence_columns:
                conn.execute(statement)
        conn.commit()
    return db_path()


@contextmanager
def connect():
    initialize()
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def audit(conn: sqlite3.Connection, action: str, data: dict, engagement_id: int | None = None) -> None:
    conn.execute(
        "INSERT INTO audit(engagement_id,action,data,created_at) VALUES(?,?,?,?)",
        (engagement_id, action, json.dumps(data, sort_keys=True), now()),
    )


def engagement(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM engagements WHERE name=?", (name,)).fetchone()
    if not row:
        raise ValueError(f"Unknown engagement: {name}")
    return row
