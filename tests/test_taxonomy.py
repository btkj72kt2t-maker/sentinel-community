import unittest

from sentinel.catalog import capability_catalog
from sentinel.taxonomy import FAMILIES, coverage_matrix, recommendations


class TaxonomyTests(unittest.TestCase):
    def test_source_and_modern_families_are_covered(self):
        names = {item["id"] for item in FAMILIES}
        self.assertTrue({"access-control", "injection", "cache-proxy", "wireless-device", "source-binary"}.issubset(names))
        coverage = coverage_matrix()
        self.assertGreaterEqual(len(coverage["families"]), 15)
        self.assertEqual(coverage["summary"]["blind_spots"], [])
        self.assertEqual(coverage["summary"]["reviewed_coverage_percent"], 100.0)
        self.assertLess(coverage["summary"]["automation_coverage_percent"], 100.0)
        self.assertIn("sentinel-artifact", next(item for item in coverage["families"] if item["id"] == "wireless-device")["reviewed_adapters"])

    def test_catalog_is_curated_and_broad(self):
        catalog = capability_catalog()
        self.assertGreaterEqual(catalog["summary"]["catalogued"], 400)
        self.assertGreaterEqual(catalog["summary"]["reference_only"], 250)
        self.assertEqual(catalog["summary"]["adapter_reviewed"], 13)
        self.assertIn("containers-kubernetes", catalog["categories"])

    def test_recommendation_mapping(self):
        result = recommendations([{"id": 7, "title": "SQL injection", "details": "parameter"}])
        self.assertEqual(result[0]["finding_id"], 7)
        self.assertIn("injection", result[0]["families"])
