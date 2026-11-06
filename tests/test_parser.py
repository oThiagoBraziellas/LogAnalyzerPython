import unittest

from log_analyzer import ParseError, parse_line

COMBINED = (
    '203.0.113.9 - alice [10/Oct/2026:13:55:36 +0000] "GET /api/items?page=2 HTTP/1.1" '
    '200 2326 "https://example.com/" "Mozilla/5.0 (X11)" 0.123'
)


class ParserTests(unittest.TestCase):
    def test_combined_with_request_time(self):
        e = parse_line(COMBINED)
        self.assertEqual(e.ip, "203.0.113.9")
        self.assertEqual(e.user, "alice")
        self.assertEqual((e.method, e.path, e.protocol), ("GET", "/api/items", "HTTP/1.1"))
        self.assertEqual((e.status, e.bytes_sent), (200, 2326))
        self.assertEqual(e.referer, "https://example.com/")
        self.assertEqual(e.user_agent, "Mozilla/5.0 (X11)")
        self.assertAlmostEqual(e.request_time, 0.123)
        self.assertEqual(e.timestamp.year, 2026)
        self.assertEqual(e.timestamp.utcoffset().total_seconds(), 0)

    def test_quoted_request_time(self):
        e = parse_line(COMBINED[:-5] + '"0.500"')
        self.assertAlmostEqual(e.request_time, 0.5)

    def test_without_request_time(self):
        e = parse_line(COMBINED.rsplit(" ", 1)[0])
        self.assertIsNone(e.request_time)
        self.assertEqual(e.status, 200)

    def test_common_log_format(self):
        e = parse_line('1.2.3.4 - - [10/Oct/2026:13:55:36 -0300] "POST /x HTTP/1.0" 201 -')
        self.assertEqual((e.method, e.path, e.status, e.bytes_sent), ("POST", "/x", 201, 0))
        self.assertIsNone(e.referer)
        self.assertEqual(e.timestamp.utcoffset().total_seconds(), -3 * 3600)

    def test_dash_bytes_and_referer(self):
        e = parse_line('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 304 - "-" "curl/8" 0.001')
        self.assertEqual(e.bytes_sent, 0)
        self.assertIsNone(e.referer)

    def test_query_string_and_fragment_removed(self):
        e = parse_line(COMBINED.replace("/api/items?page=2", "/a/b?x=1#frag"))
        self.assertEqual(e.path, "/a/b")

    def test_escaped_quote_in_user_agent(self):
        e = parse_line(COMBINED.replace("Mozilla/5.0 (X11)", 'Agent \\"quoted\\"'))
        self.assertIn("quoted", e.user_agent)

    def test_garbage_request_is_kept(self):
        e = parse_line('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "\\x16\\x03\\x01" 400 150 "-" "-" 0.000')
        self.assertEqual(e.method, "-")
        self.assertEqual(e.status, 400)

    def test_rejects_garbage(self):
        for bad in ["", "hello world", "1.2.3.4 - - [bad date] \"GET / HTTP/1.1\" 200 1"]:
            with self.assertRaises(ParseError, msg=bad):
                parse_line(bad)


if __name__ == "__main__":
    unittest.main()
