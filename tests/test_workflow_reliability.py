import os
import tempfile
import unittest
from unittest.mock import patch

from sentinel.db import connect, now
from sentinel.tools import REGISTRY
from sentinel.workflow import create_workflow, run_workflow


class WorkflowReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            eid = conn.execute("INSERT INTO engagements(name,active_enabled,created_at) VALUES('demo',1,?)", (now(),)).lastrowid
            conn.execute("INSERT INTO scope(engagement_id,kind,value,allow_subdomains) VALUES(?,'domain','example.com',0)", (eid,))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    @patch("sentinel.workflow.execute", side_effect=OSError("adapter crashed"))
    @patch("sentinel.workflow.command_for")
    def test_three_consecutive_adapter_failures_open_circuit(self, command_for, _execute):
        command_for.side_effect = lambda tool, profile, target: (REGISTRY[tool], [f"/tools/{tool}", target])
        workflow_id = create_workflow("demo", "example.com", "passive")
        result = run_workflow(workflow_id)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("circuit breaker", result["steps"][-1]["message"])
        with connect() as conn:
            event = conn.execute("SELECT action FROM audit WHERE action='workflow.circuit_breaker'").fetchone()
        self.assertIsNotNone(event)


if __name__ == "__main__":
    unittest.main()
