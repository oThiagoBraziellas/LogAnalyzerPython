import unittest

from log_analyzer import Analyzer, analyze_lines, percentile


def line(path="/", status=200, rt=None, ip="1.1.1.1", sec=0, size=100):
    tail = f" {rt}" if rt is not None else ""
    return (
        f'{ip} - - [10/Oct/2026:13:00:{sec:02d} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "ua"{tail}'
    )


class PercentileTests(unittest.TestCase):
    def test_nearest_rank(self):
        data = list(range(1, 101))
        self.assertEqual(percentile(data, 95), 95)
        self.assertEqual(percentile(data, 50), 50)
        self.assertEqual(percentile(data, 100), 100)
        self.assertEqual(percentile(data, 0), 1)

    def test_small_inputs(self):
        self.assertEqual(percentile([5], 95), 5)
        self.assertEqual(percentile([1, 2], 95), 2)

    def test_errors(self):
        with self.assertRaises(ValueError):
            percentile([], 50)
        with self.assertRaises(ValueError):
            percentile([1], 101)


class AnalyzerTests(unittest.TestCase):
    def test_counts_and_ordering(self):
        lines = [line("/a"), line("/b"), line("/a"), line("/a", 404), line("/b", 500), line("/c", 200)]
        r = analyze_lines(lines, top=2)
        self.assertEqual(r.total, 6)
        self.assertEqual(r.top_paths, [("/a", 3), ("/b", 2)])
        self.assertEqual(r.status_counts, {200: 4, 404: 1, 500: 1})
        self.assertEqual(r.status_classes, {"2xx": 4, "4xx": 1, "5xx": 1})
        self.assertAlmostEqual(r.error_rate, 2 / 6)

    def test_ties_are_sorted_by_name(self):
        r = analyze_lines([line("/z"), line("/m"), line("/a")], top=3)
        self.assertEqual([p for p, _ in r.top_paths], ["/a", "/m", "/z"])

    def test_p95_latency(self):
        lines = [line(rt=f"{i / 100:.2f}") for i in range(1, 101)]  # 0.01 .. 1.00
        r = analyze_lines(lines)
        self.assertAlmostEqual(r.latency["p95"], 0.95)
        self.assertAlmostEqual(r.latency["p50"], 0.50)
        self.assertAlmostEqual(r.latency["max"], 1.0)
        self.assertEqual(r.latency_samples, 100)

    def test_no_latency_data(self):
        r = analyze_lines([line()])
        self.assertEqual(r.latency, {})

    def test_malformed_and_blank_lines(self):
        r = analyze_lines([line(), "garbage", "", "   ", line()])
        self.assertEqual((r.total, r.malformed), (2, 1))

    def test_bytes_and_period(self):
        r = analyze_lines([line(sec=30, size=10), line(sec=5, size=20), line(sec=59, size=30)])
        self.assertEqual(r.bytes_total, 60)
        self.assertEqual(r.first_seen.second, 5)
        self.assertEqual(r.last_seen.second, 59)

    def test_slowest_paths_need_enough_samples(self):
        lines = [line("/slow", rt=2.0) for _ in range(5)] + [line("/fast", rt=0.1) for _ in range(5)]
        lines.append(line("/once", rt=99.0))
        r = analyze_lines(lines)
        self.assertEqual([p for p, _ in r.slowest_paths], ["/slow", "/fast"])

    def test_streaming_accepts_an_iterator(self):
        def gen():
            for i in range(1000):
                yield line(f"/p{i % 3}", rt=0.1)

        r = analyze_lines(gen())
        self.assertEqual(r.total, 1000)

    def test_reservoir_bounds_memory_and_keeps_estimate_reasonable(self):
        a = Analyzer(max_latency_samples=500, seed=1)
        for i in range(20000):
            a.add_line(line(rt=f"{(i % 100) / 100:.2f}"))
        r = a.report()
        self.assertEqual(r.latency_samples, 500)
        self.assertEqual(r.total, 20000)
        self.assertAlmostEqual(r.latency["p95"], 0.95, delta=0.06)

    def test_to_dict_is_json_serialisable(self):
        import json

        r = analyze_lines([line(rt=0.2), line("/x", 500, rt=0.4)])
        data = json.loads(json.dumps(r.to_dict()))
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["status_counts"]["500"], 1)


if __name__ == "__main__":
    unittest.main()
