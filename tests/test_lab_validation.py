import unittest
from unittest.mock import patch

from sentinel.lab_validation import _loopback_host


class LabValidationTests(unittest.TestCase):
    def test_localhost_is_allowed(self):
        self.assertTrue(_loopback_host("localhost"))

    @patch("sentinel.lab_validation.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("192.0.2.10", 0))])
    def test_non_loopback_is_rejected(self, _lookup):
        self.assertFalse(_loopback_host("example.test"))


if __name__ == "__main__":
    unittest.main()
