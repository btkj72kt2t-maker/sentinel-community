import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.health import check_health


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_detects_missing_evidence(self):
        with connect() as conn:
            eid = conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),)).lastrowid
            conn.execute("INSERT INTO evidence(engagement_id,original_name,stored_path,sha256,size,created_at) VALUES(?,?,?,?,?,?)", (eid, "missing.txt", str(Path(self.temp.name) / "missing.txt"), "0" * 64, 1, now()))
        result = check_health("demo")
        self.assertFalse(result["healthy"])
        evidence_check = next(c for c in result["checks"] if c["check"] == "evidence_integrity")
        self.assertEqual(evidence_check["missing"], [1])


if __name__ == "__main__":
    unittest.main()
