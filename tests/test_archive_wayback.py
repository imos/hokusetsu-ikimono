import sys
import tempfile
import unittest
import urllib.error
import contextlib
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import archive_wayback  # noqa: E402


class DownloadFallbackTest(unittest.TestCase):
    def test_fallback_to_www_when_original_fails(self):
        original = (
            "http://hokusetsu-ikimono.com/butterfly/mesugurohyoumion/"
            "110624mesugurohyoumon-01.jpg"
        )
        fallback = (
            "http://www.hokusetsu-ikimono.com/butterfly/mesugurohyoumion/"
            "110624mesugurohyoumon-01.jpg"
        )
        captures = {
            original: ["20190101000000"],
            fallback: ["20190619003844"],
        }
        fallback_cache = {}

        def fake_fetcher(_url):
            raise AssertionError("fetcher should not be called")

        def fake_downloader(archive_url, dest_path):
            if "id_/http://hokusetsu-ikimono.com/" in archive_url:
                raise RuntimeError("HTTP 404")
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"ok")
            return {
                "status": 200,
                "content_type": "image/jpeg",
                "content_length": "2",
                "effective_url": archive_url,
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir) / "output.jpg"
            success, selected_original, selected_timestamp, meta, last_error = (
                archive_wayback.download_with_fallback(
                    original,
                    dest_path,
                    captures,
                    fallback_cache,
                    fake_fetcher,
                    fake_downloader,
                )
            )

            self.assertTrue(success, msg=last_error)
            self.assertEqual(selected_original, fallback)
            self.assertEqual(selected_timestamp, "20190619003844")
            self.assertTrue(meta)
            self.assertTrue(dest_path.exists())

    def test_get_timestamps_handles_fetcher_error(self):
        original = "http://hokusetsu-ikimono.com/example.jpg"
        captures = {}
        fallback_cache = {}

        def fake_fetcher(_url):
            raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))

        with contextlib.redirect_stderr(io.StringIO()):
            timestamps = archive_wayback.get_timestamps_for_url(
                original,
                captures,
                fallback_cache,
                fake_fetcher,
            )

        self.assertEqual(timestamps, [])
        self.assertIn(original, fallback_cache)
        self.assertEqual(fallback_cache[original], [])


if __name__ == "__main__":
    unittest.main()
