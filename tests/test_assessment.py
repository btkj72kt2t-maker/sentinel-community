import unittest
from unittest.mock import patch

from sentinel.assessment import run_assessment
from sentinel.workflow import PROFILES


class AssessmentTests(unittest.TestCase):
    def test_complete_profile_orders_every_reviewed_adapter(self):
        self.assertEqual([step.tool for step in PROFILES["complete-safe"]], ["dig", "whois", "subfinder", "naabu", "httpx", "katana", "feroxbuster", "whatweb", "testssl.sh", "nmap", "nuclei"])

    @patch("sentinel.assessment.run_workflow")
    @patch("sentinel.assessment.create_workflow", return_value=42)
    @patch("sentinel.assessment.certify", return_value={"summary": {"failed": 0}, "adapters": [], "adapter_binaries": []})
    def test_dry_run_stops_before_post_processing(self, _certify, _create, run):
        run.return_value = {"status": "completed", "steps": []}
        result = run_assessment("demo", "example.com", dry_run=True)
        self.assertFalse(result["completed"])
        self.assertEqual(result["workflow_id"], 42)
        run.assert_called_once_with(42, approve_active=False, dry_run=True)

    @patch("sentinel.assessment.run_workflow", return_value={"status": "blocked", "steps": []})
    @patch("sentinel.assessment.create_workflow", return_value=8)
    @patch("sentinel.assessment.certify", return_value={"summary": {"failed": 0}, "adapters": [], "adapter_binaries": []})
    def test_policy_block_prevents_post_processing(self, _certify, _create, _run):
        result = run_assessment("demo", "example.com")
        self.assertEqual(result["reason"], "policy blocked execution")

    @patch("sentinel.assessment.certify", return_value={"summary": {"failed": 1}, "adapters": [{"name": "nmap", "status": "failed"}], "adapter_binaries": []})
    def test_failed_preflight_stops_before_workflow(self, _certify):
        result = run_assessment("demo", "example.com")
        self.assertEqual(result["reason"], "preflight certification failed")


if __name__ == "__main__":
    unittest.main()
