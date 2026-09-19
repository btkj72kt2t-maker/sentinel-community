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

    @patch("sentinel.tools.shutil.which", return_value="/usr/bin/naabu")
    def test_naabu_is_bounded(self, _which):
        _spec, command = command_for("naabu", "safe", "example.com")
        self.assertIn("-rate", command)
        self.assertIn("-top-ports", command)

    @patch("sentinel.tools.shutil.which", return_value="/usr/bin/katana")
    def test_katana_is_bounded(self, _which):
        _spec, command = command_for("katana", "safe", "example.com")
        self.assertIn("-host-rate-limit", command)
        self.assertIn("-depth", command)

    @patch("sentinel.tools.shutil.which", return_value="/usr/bin/dnsx")
    def test_dnsx_is_machine_readable_and_rate_limited(self, _which):
        _spec, command = command_for("dnsx", "safe", "example.com")
        self.assertIn("-j", command)
        self.assertIn("-rl", command)

    @patch("sentinel.tools.shutil.which", return_value="/usr/bin/tlsx")
    def test_tlsx_is_bounded_and_verifies_certificates(self, _which):
        _spec, command = command_for("tlsx", "safe", "example.com")
        self.assertIn("-verify-cert", command)
        self.assertIn("-c", command)
        self.assertIn("-delay", command)


if __name__ == "__main__":
    unittest.main()
