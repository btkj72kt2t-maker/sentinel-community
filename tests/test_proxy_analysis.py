import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.proxy_analysis import analyze_har


class ProxyAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            eid = conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),)).lastrowid
            conn.execute("INSERT INTO scope(engagement_id,kind,value,allow_subdomains) VALUES(?,'domain','example.com',1)", (eid,))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_har_is_scoped_and_redacts_authorization(self):
        payload = {"log": {"entries": [
            {"request": {"method": "GET", "url": "http://api.example.com/a", "headers": [{"name": "Authorization", "value": "Bearer secret"}]}, "response": {"status": 200, "headers": []}},
            {"request": {"method": "GET", "url": "http://outside.test/", "headers": []}, "response": {"status": 200, "headers": []}},
        ]}}
        path = Path(self.temp.name) / "traffic.har"
        path.write_text(json.dumps(payload))
        result = analyze_har("demo", path)
        self.assertGreater(result["in_scope_observations"], 0)
        rendered = json.dumps(result)
        self.assertNotIn("Bearer secret", rendered)
        self.assertNotIn("outside.test", rendered)


if __name__ == "__main__":
    unittest.main()
