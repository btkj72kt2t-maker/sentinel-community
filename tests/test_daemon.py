import os
import tempfile
import unittest
from unittest.mock import patch

from sentinel.daemon import daemon_status, request_stop
from sentinel.db import connect, now


class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()
        with connect() as conn:
            conn.execute("INSERT INTO engagements(name,created_at) VALUES('demo',?)", (now(),))

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_stop_file_is_visible_in_status(self):
        request_stop("demo")
        self.assertTrue(daemon_status("demo")["stop_requested"])


if __name__ == "__main__":
    unittest.main()
