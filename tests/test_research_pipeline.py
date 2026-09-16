import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.corpus import corpus_stats, ingest_corpus
from sentinel.coverage import import_coverage
from sentinel.db import connect, now
from sentinel.novelty import record_reproduction, score_candidate
from sentinel.research import create_campaign, triage_crash


class ResearchPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.write_text("fixture")
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        with connect() as conn:
            conn.execute("INSERT INTO engagements(name,lab_mode,created_at) VALUES('lab',1,?)", (now(),))
        self.campaign = create_campaign("lab", "pipeline", "libfuzzer", self.target, self.corpus)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_corpus_deduplicates_by_content(self):
        (self.corpus / "a").write_bytes(b"same")
        (self.corpus / "b").write_bytes(b"same")
        result = ingest_corpus(self.campaign, self.corpus)
        self.assertEqual(result["stored"], 1)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(corpus_stats(self.campaign)["count"], 1)

    def test_coverage_delta(self):
        path = self.root / "coverage.json"
        path.write_text(json.dumps({"executions": 100, "edges": 20, "paths": 4, "crashes": 0, "hangs": 0}))
        first = import_coverage(self.campaign, path)
        self.assertEqual(first["delta"]["edges"], 20)
        path.write_text(json.dumps({"executions": 250, "edges": 25, "paths": 6, "crashes": 1, "hangs": 0}))
        second = import_coverage(self.campaign, path)
        self.assertEqual(second["delta"]["edges"], 5)

    def test_candidate_requires_reproduction_and_sanitizer(self):
        log = self.root / "crash.log"
        log.write_text("heap-buffer-overflow\n#0 0x1234 in parse parser.c:1")
        triage_crash(self.campaign, log)
        with connect() as conn:
            crash_id = conn.execute("SELECT id FROM crashes WHERE campaign_id=?", (self.campaign,)).fetchone()[0]
        crash_input = self.root / "input"
        crash_input.write_bytes(b"boom")
        record_reproduction(crash_id, crash_input, "reproduced", "ASan")
        self.assertEqual(score_candidate(crash_id)["classification"], "needs-more-evidence")
        record_reproduction(crash_id, crash_input, "reproduced", "ASan")
        self.assertEqual(score_candidate(crash_id)["classification"], "zero-day-candidate")


if __name__ == "__main__":
    unittest.main()
