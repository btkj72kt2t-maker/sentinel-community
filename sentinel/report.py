from __future__ import annotations

import html
import json
from pathlib import Path

from .config import reports_dir
from .db import connect, engagement


def build_report(name: str) -> tuple[Path, Path]:
    with connect() as conn:
        eng = engagement(conn, name)
        eid = eng["id"]
        payload = {
            "engagement": dict(eng),
            "scope": [dict(r) for r in conn.execute("SELECT * FROM scope WHERE engagement_id=?", (eid,))],
            "entities": [dict(r) for r in conn.execute("SELECT * FROM entities WHERE engagement_id=?", (eid,))],
            "relationships": [dict(r) for r in conn.execute("SELECT * FROM relationships WHERE engagement_id=?", (eid,))],
            "findings": [dict(r) for r in conn.execute("SELECT * FROM findings WHERE engagement_id=? ORDER BY id", (eid,))],
            "evidence": [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE engagement_id=?", (eid,))],
            "tool_runs": [dict(r) for r in conn.execute("SELECT * FROM tool_runs WHERE engagement_id=? ORDER BY id", (eid,))],
            "workflows": [dict(r) for r in conn.execute("SELECT * FROM workflows WHERE engagement_id=? ORDER BY id", (eid,))],
            "audit": [dict(r) for r in conn.execute("SELECT * FROM audit WHERE engagement_id=? ORDER BY id", (eid,))],
        }
    reports_dir().mkdir(parents=True, exist_ok=True)
    json_path = reports_dir() / f"{name}.json"
    html_path = reports_dir() / f"{name}.html"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    rows = "".join(
        f"<tr><td>{html.escape(f['severity'])}</td><td>{html.escape(f['target'])}</td><td>{html.escape(f['title'])}</td></tr>"
        for f in payload["findings"]
    ) or "<tr><td colspan='3'>No findings recorded</td></tr>"
    page = f"""<!doctype html><html><head><meta charset='utf-8'><title>Sentinel — {html.escape(name)}</title>
<style>body{{background:#070b0a;color:#b7ffca;font:15px ui-monospace,monospace;margin:40px}}h1{{color:#55ff88}}section{{border:1px solid #225b36;padding:18px;margin:16px 0}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #225b36;padding:9px;text-align:left}}.muted{{color:#7aaa87}}</style></head>
<body><h1>SENTINEL // {html.escape(name)}</h1><p class='muted'>Authorized security engagement report</p>
<section><h2>Scope</h2><pre>{html.escape(json.dumps(payload['scope'], indent=2))}</pre></section>
<section><h2>Findings</h2><table><tr><th>Severity</th><th>Target</th><th>Title</th></tr>{rows}</table></section>
<section><h2>Graph</h2><p>{len(payload['entities'])} entities · {len(payload['relationships'])} relationships</p></section>
<section><h2>Tool runs</h2><pre>{html.escape(json.dumps(payload['tool_runs'], indent=2))}</pre></section>
<section><h2>Workflows</h2><pre>{html.escape(json.dumps(payload['workflows'], indent=2))}</pre></section>
<section><h2>Evidence</h2><pre>{html.escape(json.dumps(payload['evidence'], indent=2))}</pre></section></body></html>"""
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path
