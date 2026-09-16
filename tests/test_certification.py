import unittest
from unittest.mock import patch

from sentinel.certification import _adapter_check, _binary_check, certify


class CertificationTests(unittest.TestCase):
    def test_every_adapter_builds_argument_arrays(self):
        report = certify(probe_versions=False)
        self.assertTrue(all(item["status"] == "passed" for item in report["adapters"]))

    def test_unknown_binary_is_untested(self):
        self.assertEqual(_binary_check("missing", None, probe=False)["status"], "untested")

    def test_adapter_target_is_separate_argument(self):
        result = _adapter_check("nmap")
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["profiles"][0]["target_is_separate_argument"])

    @patch("sentinel.certification.os.access", return_value=False)
    def test_non_executable_binary_fails(self, _access):
        result = _binary_check("python", __file__, probe=False)
        self.assertEqual(result["status"], "failed")
