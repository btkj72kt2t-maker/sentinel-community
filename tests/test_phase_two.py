import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.api_analysis import analyze_openapi
from sentinel.db import connect, now
from sentinel.provenance import executable_manifest
from sentinel.scheduling import add_schedule, list_schedules
from sentinel.validation import correlate_findings


class PhaseTwoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            self.eid = conn.execute("INSERT INTO engagements(name,active_enabled,created_at) VALUES('demo',1,?)", (now(),)).lastrowid
            conn.execute("INSERT INTO scope(engagement_id,kind,value,allow_subdomains) VALUES(?,?,?,1)", (self.eid, "domain", "example.com"))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_cross_tool_findings_are_confirmed(self):
        with connect() as conn:
            for source in ("scanner-a", "scanner-b"):
                conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)", (self.eid, "example.com", source, "high", "Missing authorization check", "{}", now()))
        result = correlate_findings("demo")
        self.assertEqual(result["groups"][0]["status"], "confirmed")
        self.assertEqual(len(result["groups"][0]["sources"]), 2)

    def test_openapi_analysis_is_offline_and_scoped(self):
        spec = Path(self.temp.name) / "api.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}], "paths": {"/users/{id}": {"get": {"parameters": [{"in": "path", "name": "id"}]}}}}))
        result = analyze_openapi("demo", spec)
        self.assertEqual(result["mode"], "offline")
        self.assertEqual(result["operations"], 1)
        self.assertEqual(result["observations"], 2)

    def test_openapi_rejects_out_of_scope_server(self):
        spec = Path(self.temp.name) / "bad.json"
        spec.write_text(json.dumps({"openapi": "3.0.3", "servers": [{"url": "https://outside.test"}], "paths": {}}))
        with self.assertRaises(PermissionError):
            analyze_openapi("demo", spec)

    def test_schedule_has_minimum_interval(self):
        schedule_id = add_schedule("demo", "example.com", "passive", 1)
        item = list_schedules("demo")[0]
        self.assertEqual(item["id"], schedule_id)
        self.assertEqual(item["interval_seconds"], 300)

    def test_schedule_rejects_out_of_scope_target(self):
        with self.assertRaises(PermissionError):
            add_schedule("demo", "outside.test", "passive", 3600)

    def test_provenance_only_contains_reviewed_adapters(self):
        names = {item["name"] for item in executable_manifest()["executables"]}
        self.assertNotIn("python-extension", names)


if __name__ == "__main__":
    unittest.main()
