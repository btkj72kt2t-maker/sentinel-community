import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.token_analysis import analyze_jwt


def _segment(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


class TokenAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_unsigned_token_is_flagged_without_storing_token(self):
        raw = f"{_segment({'alg': 'none', 'typ': 'JWT'})}.{_segment({'sub': 'user', 'iat': 1, 'exp': 200000})}."
        path = Path(self.temp.name) / "token.txt"
        path.write_text(raw)
        result = analyze_jwt("demo", path, at_time=100)
        rendered = json.dumps(result)
        self.assertTrue(any(item["severity"] == "critical" for item in result["findings"]))
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["token_stored"])
        self.assertNotIn(raw, rendered)


if __name__ == "__main__":
    unittest.main()
