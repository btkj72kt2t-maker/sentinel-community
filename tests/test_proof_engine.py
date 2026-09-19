import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.callback_lab import issue_token, list_events, record_callback
from sentinel.db import connect, now
from sentinel.differential import analyze_authorization_matrix, analyze_differential
from sentinel.disclosure import build_disclosure
from sentinel.proof_engine import plan_proof, start_proof


class ProofEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            self.lab_id = conn.execute("INSERT INTO engagements(name,active_enabled,lab_mode,created_at) VALUES('lab',1,1,?)", (now(),)).lastrowid
            self.live_id = conn.execute("INSERT INTO engagements(name,active_enabled,lab_mode,created_at) VALUES('live',1,0,?)", (now(),)).lastrowid
            self.lab_finding = conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)", (self.lab_id, "localhost", "test", "high", "Possible SQL injection", json.dumps({"token": "do-not-export", "confidence": 0.8}), now())).lastrowid
            self.live_finding = conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)", (self.live_id, "example.com", "test", "high", "Possible IDOR authorization issue", "{}", now())).lastrowid

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def write_json(self, name, value):
        path = Path(self.temp.name) / name
        path.write_text(json.dumps(value))
        return path

    def test_module_selection_and_lab_gate(self):
        plan = plan_proof("lab", self.lab_finding)
        self.assertEqual(plan["modules"][0]["module_id"], "injection-differential")
        result = start_proof("lab", self.lab_finding, "injection-differential", approved=True)
        self.assertEqual(result["status"], "ready")
        with self.assertRaises(PermissionError):
            start_proof("live", self.live_finding, "authorization-differential")

    def test_differential_redacts_sensitive_headers(self):
        path = self.write_json("diff.json", {"baseline": {"status": 403, "headers": {"Authorization": "secret"}, "body": "denied"}, "variant": {"status": 200, "headers": {"Set-Cookie": "secret"}, "body": "record"}})
        result = analyze_differential("live", self.live_finding, path)
        self.assertEqual(result["interpretation"], "possible-authorization-bypass")
        self.assertEqual(result["baseline"]["headers"]["Authorization"], "[REDACTED]")

    def test_authorization_matrix_finds_violation(self):
        path = self.write_json("matrix.json", {"observations": [{"role": "viewer", "resource": "invoice-2", "action": "read", "expected_allowed": False, "observed_allowed": True}]})
        result = analyze_authorization_matrix("live", self.live_finding, path)
        self.assertEqual(result["status"], "violations-found")

    def test_loopback_callback_evidence(self):
        issued = issue_token("lab", self.lab_finding, 60)
        self.assertTrue(record_callback(issued["token"], "GET", f"/{issued['token']}", headers={"Authorization": "secret", "User-Agent": "test"}))
        events = list_events("lab")
        self.assertEqual(len(events), 1)
        self.assertNotIn("Authorization", events[0]["headers"])
        self.assertFalse(record_callback(issued["token"], "GET", "/outside", source="192.0.2.1"))

    def test_disclosure_is_redacted_and_hashed(self):
        result = build_disclosure("lab", self.lab_finding)
        payload = json.loads(Path(result["path"]).read_text())
        self.assertEqual(payload["finding"]["details"]["token"], "[REDACTED]")
        self.assertEqual(len(result["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
