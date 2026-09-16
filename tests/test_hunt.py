import unittest
from unittest.mock import patch

from sentinel.hunt import run_hunt


class HuntTests(unittest.TestCase):
    @patch("sentinel.hunt.run_workflow")
    @patch("sentinel.hunt.create_workflow")
    def test_full_safe_composes_web_and_network(self, create, run):
        create.side_effect = [11, 12]
        run.side_effect = [{"status": "completed"}, {"status": "completed"}]
        result = run_hunt("eng", "example.com", dry_run=True)
        self.assertEqual(create.call_count, 2)
        self.assertEqual(run.call_count, 2)
        self.assertIsNone(result["report"])

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            run_hunt("eng", "example.com", "everything")
