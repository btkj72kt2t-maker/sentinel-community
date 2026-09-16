from __future__ import annotations

import shutil

from .db import connect


def sandbox_plan(campaign_id: int) -> dict:
    with connect() as conn:
        campaign = conn.execute("SELECT r.*,e.lab_mode FROM research_campaigns r JOIN engagements e ON e.id=r.engagement_id WHERE r.id=?", (campaign_id,)).fetchone()
        if not campaign:
            raise ValueError("unknown campaign")
        if not campaign["lab_mode"]:
            raise PermissionError("sandbox workers require a lab engagement")
    backend = "bubblewrap" if shutil.which("bwrap") else "firejail" if shutil.which("firejail") else None
    return {"campaign_id": campaign_id, "backend": backend, "ready": bool(backend), "controls": ["network namespace disabled", "read-only system", "private temporary directory", "bounded runtime", "bounded memory and CPU", "dedicated corpus/output mounts"], "target": campaign["target_path"], "note": "No target is executed until a supported sandbox backend is installed and an explicit worker approval is implemented"}

