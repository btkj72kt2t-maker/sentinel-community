import unittest

from sentinel.benchmark import run_benchmarks


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_discloses_environment(self):
        result = run_benchmarks(10)
        self.assertIn("environment", result)
        self.assertEqual(result["json_roundtrip"]["iterations"], 10)
        self.assertIn("not a network-throughput claim", result["note"])


if __name__ == "__main__":
    unittest.main()
