from __future__ import annotations

import html
import json
from pathlib import Path

from .config import reports_dir
from .db import connect, engagement
from .taxonomy import coverage_matrix


def build_dashboard(name: str) -> Path:
    with connect() as conn:
        eng = engagement(conn, name)
        eid = eng["id"]
        findings = [dict(r) for r in conn.execute("SELECT severity,status,title,target,risk_score FROM findings WHERE engagement_id=? ORDER BY risk_score DESC,id DESC", (eid,))]
        jobs = [dict(r) for r in conn.execute("SELECT id,kind,status,created_at,finished_at FROM jobs WHERE engagement_id=? ORDER BY id DESC LIMIT 25", (eid,))]
        workflows = [dict(r) for r in conn.execute("SELECT id,profile,target,status,updated_at FROM workflows WHERE engagement_id=? ORDER BY id DESC LIMIT 25", (eid,))]
    coverage = coverage_matrix()["summary"]
    rows = "".join(f"<tr><td>{html.escape(str(f['severity']))}</td><td>{html.escape(str(f['status']))}</td><td>{html.escape(str(f['target']))}</td><td>{html.escape(str(f['title']))}</td><td>{f['risk_score'] or 0}</td></tr>" for f in findings) or "<tr><td colspan=5>No findings</td></tr>"
    page = f"""<!doctype html><meta charset=utf-8><title>Sentinel Operations</title><style>body{{font:14px system-ui;background:#07100b;color:#d8ffe3;margin:32px}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}section{{border:1px solid #28613a;border-radius:10px;padding:16px;margin:14px 0}}b{{font-size:26px;color:#63ff91}}table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border-bottom:1px solid #21472d;text-align:left}}</style><h1>SENTINEL // {html.escape(name)}</h1><p>Authorized engagement operator snapshot · kill switch: {'ACTIVE' if eng['kill_switch'] else 'ready'}</p><div class=grid><section><b>{len(findings)}</b><br>findings</section><section><b>{coverage['families']}</b><br>coverage families</section><section><b>{coverage['with_installed_tools']}</b><br>families with installed tooling</section></div><section><h2>Findings</h2><table><tr><th>Severity</th><th>Validation</th><th>Target</th><th>Finding</th><th>Risk</th></tr>{rows}</table></section><section><h2>Recent workflows</h2><pre>{html.escape(json.dumps(workflows, indent=2))}</pre></section><section><h2>Recent jobs</h2><pre>{html.escape(json.dumps(jobs, indent=2))}</pre></section>"""
    reports_dir().mkdir(parents=True, exist_ok=True)
    path = reports_dir() / f"{name}-dashboard.html"
    path.write_text(page, encoding="utf-8")
    return path
