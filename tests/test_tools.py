import unittest
from unittest.mock import patch

from sentinel.tools import command_for, inventory


class ToolRegistryTests(unittest.TestCase):
    @patch("sentinel.tools.shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_safe_profile_is_rate_limited(self, _which):
        spec, command = command_for("nmap", "safe", "example.com")
        self.assertTrue(spec.active)
        self.assertIn("--max-rate", command)
        self.assertEqual(command[-1], "example.com")

    def test_inventory_has_no_arbitrary_shell_adapter(self):
        names = {item["name"] for item in inventory()}
        self.assertNotIn("shell", names)

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaises(ValueError):
            command_for("made-up-tool", "default", "example.com")


if __name__ == "__main__":
    unittest.main()
