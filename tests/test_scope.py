import unittest

from sentinel.scope import classify_scope, normalize_target, target_allowed


class ScopeTests(unittest.TestCase):
    def test_url_normalization(self):
        self.assertEqual(normalize_target("https://API.Example.com/path"), "api.example.com")

    def test_subdomain_scope(self):
        rows = [{"kind": "domain", "value": "example.com", "allow_subdomains": 1}]
        self.assertTrue(target_allowed("api.example.com", rows))
        self.assertFalse(target_allowed("example.com.attacker.test", rows))

    def test_exact_domain_scope(self):
        rows = [{"kind": "domain", "value": "example.com", "allow_subdomains": 0}]
        self.assertTrue(target_allowed("example.com", rows))
        self.assertFalse(target_allowed("api.example.com", rows))

    def test_cidr_is_strict(self):
        self.assertEqual(classify_scope("192.0.2.0/24"), ("cidr", "192.0.2.0/24"))


if __name__ == "__main__":
    unittest.main()
