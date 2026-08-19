import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.intelligence import attack_paths, score_engagement


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            cur = conn.execute("INSERT INTO engagements(name,active_enabled,created_at) VALUES('demo',0,?)", (now(),))
            self.eid = cur.lastrowid

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_risk_score_is_explainable(self):
        with connect() as conn:
            conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at) VALUES(?,?,?,?,?,?,?)", (self.eid, "example.com", "nuclei", "high", "Issue", json.dumps({"confidence": 1}), now()))
        result = score_engagement("demo")
        self.assertEqual(result["findings"][0]["score"], 75.0)
        self.assertIn("factors", result["findings"][0])

    def test_paths_follow_relationships(self):
        with connect() as conn:
            a = conn.execute("INSERT INTO entities(engagement_id,kind,value,created_at) VALUES(?,?,?,?)", (self.eid, "domain", "example.com", now())).lastrowid
            b = conn.execute("INSERT INTO entities(engagement_id,kind,value,created_at) VALUES(?,?,?,?)", (self.eid, "ip", "192.0.2.1", now())).lastrowid
            conn.execute("INSERT INTO relationships(engagement_id,source_id,target_id,relation,confidence,created_at) VALUES(?,?,?,?,?,?)", (self.eid, a, b, "resolves_to", 0.9, now()))
        result = attack_paths("demo", "example.com")
        self.assertEqual(result["paths"][0]["nodes"], ["example.com", "192.0.2.1"])


if __name__ == "__main__":
    unittest.main()
