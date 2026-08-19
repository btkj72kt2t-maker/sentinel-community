import tempfile
import unittest
from pathlib import Path

from sentinel.normalize import normalize


class NormalizeTests(unittest.TestCase):
    def fixture(self, text):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_nuclei_jsonl(self):
        path = self.fixture('{"template-id":"x","info":{"name":"Test issue","severity":"high"}}\n')
        result = normalize("nuclei", path, "example.com")
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_nmap_open_service(self):
        path = self.fixture('<nmaprun><host><address addr="192.0.2.1"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
        result = normalize("nmap", path, "example.com")
        values = {item["value"] for item in result["entities"]}
        self.assertIn("example.com:443/tcp", values)


if __name__ == "__main__":
    unittest.main()
