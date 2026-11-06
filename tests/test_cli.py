import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from log_analyzer.cli import main

LOG = (
    '1.1.1.1 - - [10/Oct/2026:13:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua" 0.100\n'
    '1.1.1.2 - - [10/Oct/2026:13:00:01 +0000] "GET /a HTTP/1.1" 500 10 "-" "ua" 0.300\n'
    "not a log line\n"
)


def run(argv, stdin=None):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        if stdin is not None:
            with mock.patch("sys.stdin", io.StringIO(stdin)):
                rc = main(argv)
        else:
            rc = main(argv)
    return rc, out.getvalue()


class CliTests(unittest.TestCase):
    def test_file_text_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "access.txt")
            with open(path, "w") as f:
                f.write(LOG)
            rc, out = run([path])
        self.assertEqual(rc, 0)
        self.assertIn("Requests: 2", out)
        self.assertIn("malformed lines: 1", out)
        self.assertIn("p95", out)

    def test_stdin_json(self):
        rc, out = run(["--json", "--top", "1"], stdin=LOG)
        data = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(data["top_paths"], [{"path": "/a", "count": 2}])
        self.assertAlmostEqual(data["latency_seconds"]["p95"], 0.3)

    def test_missing_file(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc, _ = run(["/nonexistent/file"])
        self.assertEqual(rc, 1)

    def test_bundled_sample_runs(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "samples", "access.sample")
        rc, out = run(["--json", sample])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["total"], 2000)
        self.assertEqual(data["malformed"], 0)


if __name__ == "__main__":
    unittest.main()
