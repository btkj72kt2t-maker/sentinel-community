import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.auth_analysis import analyze_auth_har
from sentinel.db import connect, now


class AuthAnalysisTests(unittest.TestCase):
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

    def test_auth_har_redacts_credentials_and_finds_session_issues(self):
        payload = {"log": {"entries": [{
            "request": {"method": "POST", "url": "https://api.example.com/change?token=super-secret", "headers": [{"name": "Cookie", "value": "session=super-secret"}]},
            "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": "session=super-secret; Path=/"}, {"name": "Access-Control-Allow-Origin", "value": "*"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}]},
        }, {
            "request": {"method": "GET", "url": "https://outside.test/?token=outside-secret", "headers": []},
            "response": {"status": 200, "headers": []},
        }]}}
        path = Path(self.temp.name) / "auth.har"
        path.write_text(json.dumps(payload))
        result = analyze_auth_har("demo", path)
        rendered = json.dumps(result)
        self.assertEqual(result["in_scope_entries"], 1)
        self.assertEqual(result["credentials_stored"], False)
        self.assertIn("Credential-like value transported", rendered)
        self.assertIn("Credentialed CORS", rendered)
        self.assertNotIn("super-secret", rendered)
        self.assertNotIn("outside-secret", rendered)


if __name__ == "__main__":
    unittest.main()
