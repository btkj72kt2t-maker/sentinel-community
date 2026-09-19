import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.web_validation import analyze_sql_injection_evidence, analyze_xss_evidence


class WebValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            engagement_id = conn.execute("INSERT INTO engagements(name,active_enabled,lab_mode,created_at) VALUES('web',1,0,?)", (now(),)).lastrowid
            self.finding_id = conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)", (engagement_id, "example.com", "test", "high", "Possible injection", "{}", now())).lastrowid

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def fixture(self, name, payload):
        path = Path(self.temp.name) / name
        path.write_text(json.dumps(payload))
        return path

    def test_sql_error_signal_does_not_store_bodies(self):
        path = self.fixture("sql.json", {"baseline": {"status": 200, "elapsed_ms": 20, "body": "normal"}, "variant": {"status": 500, "elapsed_ms": 25, "body": "SQL syntax error near input MySQL"}})
        result = analyze_sql_injection_evidence("web", self.finding_id, path)
        self.assertEqual(result["conclusion"], "strong-sql-injection-signal")
        self.assertNotIn("body", result["variant"])

    def test_xss_uses_inert_marker_and_does_not_claim_execution(self):
        marker = "SENTINEL_MARKER_1234"
        path = self.fixture("xss.json", {"marker": marker, "response": {"content_type": "text/html", "body": f"<p>{marker}</p>"}})
        result = analyze_xss_evidence("web", self.finding_id, path)
        self.assertEqual(result["conclusion"], "inert-marker-reflected")
        self.assertIn("not proof", result["limitations"])

    def test_xss_rejects_executable_marker(self):
        path = self.fixture("bad.json", {"marker": "<script>alert(1)</script>", "response": {"body": ""}})
        with self.assertRaises(ValueError):
            analyze_xss_evidence("web", self.finding_id, path)


if __name__ == "__main__":
    unittest.main()
