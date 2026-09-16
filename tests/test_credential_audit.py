import tempfile
import unittest
from pathlib import Path

from sentinel.credential_audit import audit_path


class CredentialAuditTests(unittest.TestCase):
    def test_secret_is_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.txt"
            path.write_text("api_key = supersecretvalue\n")
            result = audit_path(path)
        self.assertEqual(result["findings"][0]["value"], "[REDACTED]")
        self.assertNotIn("supersecretvalue", str(result))


if __name__ == "__main__":
    unittest.main()
