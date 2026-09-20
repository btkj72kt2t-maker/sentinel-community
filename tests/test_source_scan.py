import unittest
from pathlib import Path

from sentinel.source_scan import _command, _findings


class SourceScanTests(unittest.TestCase):
    def test_commands_are_fixed_and_redacting(self):
        source = Path("/tmp/source")
        gitleaks = _command("gitleaks", source)
        self.assertIn("--redact=100", gitleaks)
        self.assertNotIn("shell", gitleaks)
        trivy = _command("trivy", source)
        self.assertIn("precise", trivy)
        self.assertIn("--disable-telemetry", trivy)
        semgrep = _command("semgrep", source)
        self.assertIn("--metrics", semgrep)
        self.assertIn("off", semgrep)

    def test_gitleaks_normalization_omits_secret(self):
        findings = _findings("gitleaks", [{"RuleID": "key", "Description": "Key", "Secret": "do-not-store", "Match": "token=do-not-store", "File": "a.txt", "StartLine": 2}])
        self.assertEqual(findings[0]["details"]["redacted"], True)
        self.assertNotIn("Secret", findings[0]["details"])
        self.assertNotIn("Match", findings[0]["details"])

    def test_trivy_secret_normalization_omits_match(self):
        payload = {"Results": [{"Target": "a.txt", "Secrets": [{"RuleID": "key", "Title": "Potential key", "Severity": "HIGH", "Match": "secret", "StartLine": 1}]}]}
        finding = _findings("trivy", payload)[0]
        self.assertEqual(finding["severity"], "high")
        self.assertNotIn("Match", finding["details"])

    def test_osv_normalization(self):
        payload = {"results": [{"source": {"path": "lock"}, "packages": [{"package": {"name": "demo", "version": "1.0"}, "vulnerabilities": [{"id": "CVE-2026-0001", "aliases": []}]}]}]}
        finding = _findings("osv-scanner", payload)[0]
        self.assertIn("CVE-2026-0001", finding["title"])

    def test_semgrep_normalization_omits_source_code(self):
        payload = {"results": [{"check_id": "rule", "path": "app.py", "start": {"line": 2}, "end": {"line": 2}, "extra": {"message": "Review query", "severity": "WARNING", "lines": "secret source"}}]}
        finding = _findings("semgrep", payload)[0]
        self.assertEqual(finding["severity"], "medium")
        self.assertNotIn("lines", finding["details"])


if __name__ == "__main__":
    unittest.main()
