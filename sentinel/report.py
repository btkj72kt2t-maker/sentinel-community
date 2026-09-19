from __future__ import annotations

import html
import json
from pathlib import Path

from .config import reports_dir
from .db import connect, engagement
from .taxonomy import coverage_matrix, recommendations


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
            "jobs": [dict(r) for r in conn.execute("SELECT * FROM jobs WHERE engagement_id=? ORDER BY id", (eid,))],
            "schedules": [dict(r) for r in conn.execute("SELECT * FROM schedules WHERE engagement_id=? ORDER BY id", (eid,))],
            "proxy_observations": [dict(r) for r in conn.execute("SELECT * FROM proxy_observations WHERE engagement_id=? ORDER BY id", (eid,))],
            "research_campaigns": [dict(r) for r in conn.execute("SELECT * FROM research_campaigns WHERE engagement_id=? ORDER BY id", (eid,))],
            "research_crashes": [dict(r) for r in conn.execute("SELECT c.* FROM crashes c JOIN research_campaigns r ON r.id=c.campaign_id WHERE r.engagement_id=? ORDER BY c.id", (eid,))],
            "coverage_samples": [dict(r) for r in conn.execute("SELECT c.* FROM coverage_samples c JOIN research_campaigns r ON r.id=c.campaign_id WHERE r.engagement_id=? ORDER BY c.id", (eid,))],
            "reproductions": [dict(r) for r in conn.execute("SELECT p.* FROM reproductions p JOIN crashes c ON c.id=p.crash_id JOIN research_campaigns r ON r.id=c.campaign_id WHERE r.engagement_id=? ORDER BY p.id", (eid,))],
            "audit": [dict(r) for r in conn.execute("SELECT * FROM audit WHERE engagement_id=? ORDER BY id", (eid,))],
            "vulnerability_intelligence": [dict(r) for r in conn.execute("SELECT v.* FROM vulnerability_intelligence v WHERE EXISTS (SELECT 1 FROM finding_vulnerabilities fv JOIN findings f ON f.id=fv.finding_id WHERE fv.cve=v.cve AND f.engagement_id=?) ORDER BY v.cve", (eid,))],
            "finding_vulnerabilities": [dict(r) for r in conn.execute("SELECT fv.* FROM finding_vulnerabilities fv JOIN findings f ON f.id=fv.finding_id WHERE f.engagement_id=? ORDER BY fv.finding_id,fv.cve", (eid,))],
            "components": [dict(r) for r in conn.execute("SELECT * FROM components WHERE engagement_id=? ORDER BY name,version", (eid,))],
            "component_vulnerabilities": [dict(r) for r in conn.execute("SELECT cv.* FROM component_vulnerabilities cv JOIN components c ON c.id=cv.component_id WHERE c.engagement_id=? ORDER BY cv.cve", (eid,))],
            "validation_proofs": [dict(r) for r in conn.execute("SELECT * FROM validation_proofs WHERE engagement_id=? ORDER BY id", (eid,))],
            "proof_runs": [dict(r) for r in conn.execute("SELECT * FROM proof_runs WHERE engagement_id=? ORDER BY id", (eid,))],
            "callback_events": [dict(r) for r in conn.execute("SELECT e.*,t.finding_id FROM callback_events e JOIN callback_tokens t ON t.id=e.token_id WHERE t.engagement_id=? ORDER BY e.id", (eid,))],
        }
        payload["coverage_matrix"] = coverage_matrix()
        payload["recommendations"] = recommendations(payload["findings"])
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
<section><h2>Remediation guidance</h2><pre>{html.escape(json.dumps(payload['recommendations'], indent=2))}</pre></section>
<section><h2>Assessment coverage</h2><pre>{html.escape(json.dumps(payload['coverage_matrix']['summary'], indent=2))}</pre></section>
<section><h2>Vulnerability intelligence</h2><pre>{html.escape(json.dumps(payload['vulnerability_intelligence'], indent=2))}</pre></section>
<section><h2>Software supply chain</h2><p>{len(payload['components'])} components · {len(payload['component_vulnerabilities'])} vulnerability relationships</p><pre>{html.escape(json.dumps(payload['component_vulnerabilities'], indent=2))}</pre></section>
<section><h2>Graph</h2><p>{len(payload['entities'])} entities · {len(payload['relationships'])} relationships</p></section>
<section><h2>Tool runs</h2><pre>{html.escape(json.dumps(payload['tool_runs'], indent=2))}</pre></section>
<section><h2>Workflows</h2><pre>{html.escape(json.dumps(payload['workflows'], indent=2))}</pre></section>
<section><h2>Background jobs</h2><pre>{html.escape(json.dumps(payload['jobs'], indent=2))}</pre></section>
<section><h2>Schedules</h2><pre>{html.escape(json.dumps(payload['schedules'], indent=2))}</pre></section>
<section><h2>Proxy observations</h2><pre>{html.escape(json.dumps(payload['proxy_observations'], indent=2))}</pre></section>
<section><h2>Research campaigns</h2><pre>{html.escape(json.dumps(payload['research_campaigns'], indent=2))}</pre></section>
<section><h2>Research evidence</h2><p>{len(payload['research_crashes'])} crashes · {len(payload['reproductions'])} reproductions · {len(payload['coverage_samples'])} coverage samples</p><pre>{html.escape(json.dumps(payload['research_crashes'], indent=2))}</pre></section>
<section><h2>Lab proof evidence</h2><pre>{html.escape(json.dumps(payload['validation_proofs'], indent=2))}</pre></section>
<section><h2>Proof engine</h2><p>{len(payload['proof_runs'])} proof runs · {len(payload['callback_events'])} callback events</p><pre>{html.escape(json.dumps(payload['proof_runs'], indent=2))}</pre></section>
<section><h2>Evidence</h2><pre>{html.escape(json.dumps(payload['evidence'], indent=2))}</pre></section></body></html>"""
    html_path.write_text(page, encoding="utf-8")
    return json_path, html_path
