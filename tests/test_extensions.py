import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.extensions import install_manifest, list_extensions


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"SENTINEL_DATA_DIR": self.temp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_manifest_registers_disabled(self):
        path = Path(self.temp.name) / "sentinel-extension.json"
        path.write_text(json.dumps({"name": "example-transform", "version": "1.0.0", "category": "osint", "description": "Example"}))
        result = install_manifest(path)
        self.assertFalse(result["enabled"])
        self.assertEqual(list_extensions()[0]["name"], "example-transform")

    def test_rejects_unexpected_filename(self):
        path = Path(self.temp.name) / "plugin.json"
        path.write_text("{}")
        with self.assertRaises(ValueError):
            install_manifest(path)


if __name__ == "__main__":
    unittest.main()
