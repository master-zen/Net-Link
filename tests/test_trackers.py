from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from urllib.request import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_trackers as trackers


class TrackerPipelineTests(unittest.TestCase):
    def test_malformed_port_does_not_discard_other_trackers(self):
        candidates = trackers.split_candidates(
            "udp://good.example:6969/announce\n"
            "udp://bad.example:invalid/announce\n"
            "udp://bad.example:65536/announce\n"
            "udp://bad.example:0/announce\n"
        )
        accepted = [url for item in candidates if (url := trackers.normalize_tracker_url(item))]
        self.assertEqual(accepted, ["udp://good.example:6969/announce"])

    def test_rejects_credentials_and_ipv6_zone_identifiers(self):
        self.assertIsNone(trackers.normalize_tracker_url("https://user:pass@tracker.example/announce"))
        self.assertIsNone(trackers.normalize_tracker_url("udp://[fe80::1%eth0]:6969/announce"))
        self.assertEqual(
            trackers.normalize_tracker_url("UDP://[2001:db8::1]:6969/announce"),
            "udp://[2001:db8::1]:6969/announce",
        )

    def test_source_urls_require_https(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sources.txt"
            for unsafe in ("http://example.com/list", "file:///etc/passwd",
                           "https://user:password@example.com/list"):
                with self.subTest(url=unsafe):
                    path.write_text(unsafe + "\n", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        trackers.read_source_urls(path)
            path.write_text("https://example.com/list\nhttps://example.com/list\n", encoding="utf-8")
            self.assertEqual(trackers.read_source_urls(path), ["https://example.com/list"])

    def test_source_redirect_cannot_downgrade_https(self):
        handler = trackers.HTTPSOnlyRedirectHandler()
        request = Request("https://example.com/list")
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.net/list")


if __name__ == "__main__":
    unittest.main()
