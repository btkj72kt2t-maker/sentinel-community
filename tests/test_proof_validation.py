import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.proof_validation import record_proof


class ProofValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            self.eid = conn.execute("INSERT INTO engagements(name,lab_mode,created_at) VALUES('lab',1,?)", (now(),)).lastrowid
            self.finding_id = conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,created_at) VALUES(?,?,?,?,?,?)", (self.eid, "localhost", "lab", "high", "Test", now())).lastrowid
            conn.execute("INSERT INTO engagements(name,lab_mode,created_at) VALUES('live',0,?)", (now(),))
        self.evidence = Path(self.temp.name) / "proof.txt"
        self.evidence.write_text("sanitized proof")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_confirmed_proof_requires_rollback(self):
        with self.assertRaises(PermissionError):
            record_proof("lab", self.finding_id, self.evidence, "confirmed")

    def test_lab_proof_is_hashed_and_recorded(self):
        result = record_proof("lab", self.finding_id, self.evidence, "confirmed", rollback_verified=True)
        self.assertTrue(result["rollback_verified"])
        self.assertEqual(len(result["evidence_sha256"]), 64)

    def test_non_lab_rejected(self):
        with self.assertRaises(PermissionError):
            record_proof("live", self.finding_id, self.evidence, "inconclusive")


if __name__ == "__main__":
    unittest.main()
