from __future__ import annotations

import gzip
import hashlib
import json
import urllib.parse
import urllib.request
from pathlib import Path

from .config import data_dir
from .db import audit, connect, now
from .vulnerability_intel import import_epss, import_kev


FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}
ALLOWED_HOSTS = {"www.cisa.gov", "epss.empiricalsecurity.com"}
MAX_BYTES = 100 * 1024 * 1024


class _TrustedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
            raise PermissionError("feed redirect left the trusted HTTPS allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise PermissionError("feed URL is not in the trusted HTTPS allowlist")
    request = urllib.request.Request(url, headers={"User-Agent": "Sentinel-Community-Intelligence/1.0", "Accept": "application/json,text/csv,application/gzip"})
    opener = urllib.request.build_opener(_TrustedRedirect())
    with opener.open(request, timeout=30) as response:
        chunks, size = [], 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_BYTES:
                raise ValueError("feed exceeds the 100 MiB safety limit")
            chunks.append(block)
    return b"".join(chunks)


def sync_feed(source: str) -> dict:
    if source not in FEEDS:
        raise ValueError("unknown intelligence feed")
    raw = _download(FEEDS[source])
    content = gzip.decompress(raw) if source == "epss" else raw
    if len(content) > MAX_BYTES:
        raise ValueError("decompressed feed exceeds the 100 MiB safety limit")
    if source == "kev":
        document = json.loads(content.decode("utf-8"))
        if not isinstance(document.get("vulnerabilities"), list):
            raise ValueError("downloaded KEV feed has an unexpected structure")
        suffix = ".json"
    else:
        header = next((line for line in content.decode("utf-8").splitlines() if not line.startswith("#")), "")
        if not header.startswith("cve,epss,percentile"):
            raise ValueError("downloaded EPSS feed has an unexpected structure")
        suffix = ".csv"
    digest = hashlib.sha256(content).hexdigest()
    directory = data_dir() / "intelligence" / source
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{digest}{suffix}"
    if not destination.exists():
        destination.write_bytes(content)
    with connect() as conn:
        conn.execute("INSERT OR IGNORE INTO intelligence_feeds(source,url,sha256,stored_path,size,fetched_at) VALUES(?,?,?,?,?,?)", (source, FEEDS[source], digest, str(destination), len(content), now()))
        audit(conn, "intelligence.feed_synced", {"source": source, "sha256": digest, "size": len(content), "path": str(destination)})
    imported = import_kev(destination) if source == "kev" else import_epss(destination)
    return {"source": source, "url": FEEDS[source], "sha256": digest, "size": len(content), "stored_path": str(destination), "imported": imported}


def feed_history() -> list[dict]:
    with connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM intelligence_feeds ORDER BY id DESC")]
