"""Decode limits for gzip/deflate responses (CVE-2026-59939, Python 2 port of the 0.32.0 fix)."""
import gzip
import os
import threading
import unittest
import zlib
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from StringIO import StringIO

import httplib2

MIB = 1 << 20


def gzip_bytes(data):
    out = StringIO()
    f = gzip.GzipFile(fileobj=out, mode="wb")
    f.write(data)
    f.close()
    return out.getvalue()


def raw_deflate_bytes(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def gzip_zeros(size):
    # Compress in chunks so the test never holds the decompressed body itself.
    out = StringIO()
    f = gzip.GzipFile(fileobj=out, mode="wb")
    chunk = "\0" * MIB
    for _ in range(size // MIB):
        f.write(chunk)
    f.close()
    return out.getvalue()


def raw_deflate_zeros(size):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    chunk = "\0" * MIB
    return "".join(compressor.compress(chunk) for _ in range(size // MIB)) + compressor.flush()


def response_with(encoding):
    return httplib2.Response({"status": "200", "content-encoding": encoding})


class DecodeLimitTest(unittest.TestCase):

    body = os.urandom(256 * 1024) + "httplib2 " * 10000

    def test_gzip_small_body_decodes_as_before(self):
        response = response_with("gzip")
        content = httplib2._decompressContent(response, gzip_bytes(self.body))
        self.assertEqual(content, self.body)
        self.assertEqual(response["content-length"], str(len(self.body)))
        self.assertEqual(response["-content-encoding"], "gzip")
        self.assertNotIn("content-encoding", response)

    def test_deflate_raw_body_decodes_as_before(self):
        response = response_with("deflate")
        content = httplib2._decompressContent(response, raw_deflate_bytes(self.body))
        self.assertEqual(content, self.body)
        self.assertEqual(response["-content-encoding"], "deflate")

    def test_multi_member_gzip_decodes_as_before(self):
        content = httplib2._decompressContent(response_with("gzip"), gzip_bytes("first ") + gzip_bytes("second"))
        self.assertEqual(content, "first second")

    def test_identity_body_is_untouched(self):
        response = httplib2.Response({"status": "200"})
        self.assertEqual(httplib2._decompressContent(response, "plain"), "plain")

    def test_high_ratio_below_safe_limit_is_allowed(self):
        # The ratio is only enforced once output passes the 10 MiB safe limit.
        content = httplib2._decompressContent(response_with("gzip"), gzip_zeros(8 * MIB))
        self.assertEqual(len(content), 8 * MIB)

    def test_gzip_bomb_over_ratio_raises_failed_to_decompress(self):
        with self.assertRaises(httplib2.FailedToDecompressContent) as ctx:
            httplib2._decompressContent(response_with("gzip"), gzip_zeros(64 * MIB))
        self.assertIn("exceeds decode limits", str(ctx.exception))

    def test_deflate_bomb_over_ratio_raises_failed_to_decompress(self):
        with self.assertRaises(httplib2.FailedToDecompressContent):
            httplib2._decompressContent(response_with("deflate"), raw_deflate_zeros(64 * MIB))

    def test_hard_limit_raises_failed_to_decompress(self):
        saved = httplib2.DECODE_LIMIT_HARD
        httplib2.DECODE_LIMIT_HARD = 128 * 1024
        try:
            with self.assertRaises(httplib2.FailedToDecompressContent):
                httplib2._decompressContent(response_with("gzip"), gzip_bytes(self.body))
        finally:
            httplib2.DECODE_LIMIT_HARD = saved

    def test_corrupt_body_still_raises_failed_to_decompress(self):
        for encoding in ("gzip", "deflate"):
            with self.assertRaises(httplib2.FailedToDecompressContent):
                httplib2._decompressContent(response_with(encoding), "not compressed at all")


class _Handler(BaseHTTPRequestHandler):
    payloads = {}

    def do_GET(self):
        body = self.payloads[self.path]
        self.send_response(200)
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class DecodeLimitOverHttpTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _Handler.payloads = {"/normal": gzip_bytes("hello " * 1000), "/bomb": gzip_zeros(64 * MIB)}
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_http_request_against_local_gzip_bomb_server(self):
        response, content = httplib2.Http().request(self.base + "/normal")
        self.assertEqual(response.status, 200)
        self.assertEqual(content, "hello " * 1000)

        with self.assertRaises(httplib2.FailedToDecompressContent):
            httplib2.Http().request(self.base + "/bomb")


if __name__ == "__main__":
    unittest.main()
