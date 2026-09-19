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

    def test_naabu_service(self):
        path = self.fixture('{"host":"example.com","port":8443,"protocol":"tcp"}\n')
        result = normalize("naabu", path, "example.com")
        self.assertEqual(result["entities"][0]["value"], "example.com:8443/tcp")

    def test_katana_endpoint(self):
        path = self.fixture('{"request":{"endpoint":"https://example.com/api"}}\n')
        result = normalize("katana", path, "example.com")
        self.assertEqual(result["entities"][0]["kind"], "endpoint")

    def test_dnsx_records(self):
        path = self.fixture('{"host":"www.example.com","a":["192.0.2.10"],"aaaa":["2001:db8::10"]}\n')
        result = normalize("dnsx", path, "example.com")
        values = {item["value"] for item in result["entities"]}
        self.assertIn("www.example.com", values)
        self.assertIn("192.0.2.10", values)
        self.assertIn("2001:db8::10", values)

    def test_tlsx_misconfiguration_finding(self):
        path = self.fixture('{"host":"example.com","port":443,"expired":true}\n')
        result = normalize("tlsx", path, "example.com")
        self.assertEqual(result["entities"][0]["kind"], "tls_service")
        self.assertEqual(result["findings"][0]["title"], "Expired TLS certificate")


if __name__ == "__main__":
    unittest.main()
