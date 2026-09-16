import gzip
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.feed_sync import _download, _TrustedRedirect, sync_feed
from sentinel.stix_io import export_stix, import_stix
from sentinel.supply_chain import component_risk, import_csaf, import_cyclonedx


class _Response:
    def __init__(self, body):
        self.body = body
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size):
        block = self.body[self.offset:self.offset + size]
        self.offset += len(block)
        return block


class HorizonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            self.eid = conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),)).lastrowid

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_feed_allowlist_rejects_unknown_host(self):
        with self.assertRaises(PermissionError):
            _download("https://example.com/feed.json")

    def test_redirect_cannot_leave_allowlist(self):
        with self.assertRaises(PermissionError):
            _TrustedRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com/feed")

    @patch("sentinel.feed_sync._download")
    def test_sync_archives_and_imports_epss(self, download):
        download.return_value = gzip.compress(b"cve,epss,percentile\nCVE-2026-12345,0.8,0.9\n")
        result = sync_feed("epss")
        self.assertEqual(result["imported"]["records"], 1)
        self.assertTrue(Path(result["stored_path"]).is_file())

    def test_stix_round_trip_supported_entities(self):
        source = Path(self.temp.name) / "input.json"
        source.write_text(json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001", "objects": [{"type": "domain-name", "spec_version": "2.1", "id": "domain-name--00000000-0000-4000-8000-000000000002", "value": "example.com"}]}))
        self.assertEqual(import_stix("demo", source)["entities_created"], 1)
        output = Path(self.temp.name) / "output.json"
        self.assertEqual(export_stix("demo", output)["objects"], 1)
        self.assertEqual(json.loads(output.read_text())["type"], "bundle")

    def test_cyclonedx_vex_and_component_risk(self):
        bom = Path(self.temp.name) / "bom.json"
        bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "bom-ref": "pkg:demo", "name": "demo", "version": "1.0", "purl": "pkg:pypi/demo@1.0"}], "vulnerabilities": [{"id": "CVE-2026-12345", "affects": [{"ref": "pkg:demo"}], "analysis": {"state": "affected", "response": ["update"]}}]}))
        result = import_cyclonedx("demo", bom)
        self.assertEqual(result["vulnerability_links"], 1)
        self.assertEqual(component_risk("demo")["components"][0]["priority"], "review")

    def test_csaf_updates_remediation(self):
        csaf = Path(self.temp.name) / "advisory.json"
        csaf.write_text(json.dumps({"document": {"category": "csaf_security_advisory"}, "vulnerabilities": [{"cve": "CVE-2026-12345", "title": "Example", "remediations": [{"category": "vendor_fix", "details": "Upgrade to 2.0"}]}]}))
        self.assertEqual(import_csaf(csaf)["vulnerabilities"], 1)
        with connect() as conn:
            action = conn.execute("SELECT required_action FROM vulnerability_intelligence WHERE cve='CVE-2026-12345'").fetchone()[0]
        self.assertEqual(action, "Upgrade to 2.0")


if __name__ == "__main__":
    unittest.main()
