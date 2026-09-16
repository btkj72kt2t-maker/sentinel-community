import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.research import create_campaign, triage_crash


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        self.root = Path(self.temp.name)
        self.target = self.root / "parser"
        self.target.write_text("fixture")
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        with connect() as conn:
            conn.execute("INSERT INTO engagements(name,lab_mode,created_at) VALUES('lab',1,?)", (now(),))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_crash_deduplicates(self):
        campaign = create_campaign("lab", "parser", "afl++", self.target, self.corpus)
        log = self.root / "crash.log"
        log.write_text("ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x1234 in parse input.c:10")
        first = triage_crash(campaign, log)
        second = triage_crash(campaign, log)
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        with connect() as conn:
            row = conn.execute("SELECT occurrences FROM crashes WHERE campaign_id=?", (campaign,)).fetchone()
            self.assertEqual(row["occurrences"], 2)

    def test_non_lab_campaign_is_rejected(self):
        with connect() as conn:
            conn.execute("INSERT INTO engagements(name,lab_mode,created_at) VALUES('prod',0,?)", (now(),))
        with self.assertRaises(PermissionError):
            create_campaign("prod", "x", "afl++", self.target, self.corpus)


if __name__ == "__main__":
    unittest.main()
