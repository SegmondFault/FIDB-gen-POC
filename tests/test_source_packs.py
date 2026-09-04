from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.cli import main
from fidb_poc.source_packs import (
    load_source_pack,
    pull_source_pack,
    source_pack_status,
)
from fidb_poc.toolchain_cache import AcquisitionResult


def _catalog(path: Path, payload: bytes = b"source") -> tuple[str, int]:
    digest = hashlib.sha256(payload).hexdigest()
    path.parent.mkdir(parents=True)
    path.write_text(
        f"""schema_version = "fidb-source-pack/v1"
id = "test-pack"
label = "Test source pack"
language_id = "c"
study_path = "coverage/study.toml"
selection_date = "2026-09-02"
release_policy = "test pins"

[[source]]
rank = 1
id = "alpha"
label = "Alpha"
version = "1.0"
release_page = "https://example.invalid/releases/1.0"
url = "https://example.invalid/alpha-1.0.tar.gz"
sha256 = "{digest}"
download_bytes = {len(payload)}
filename = "alpha-1.0.tar.gz"
source_directory = "alpha-1.0"
""",
        encoding="utf-8",
    )
    return digest, len(payload)


class SourcePackTests(unittest.TestCase):
    def test_catalog_is_strict_and_ordered(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sources/test-pack.toml"
            digest, _ = _catalog(path)

            pack = load_source_pack(path)

            self.assertEqual(pack["id"], "test-pack")
            self.assertEqual(pack["source"][0]["sha256"], digest)
            self.assertEqual(len(pack["catalog_sha256"]), 64)

    def test_top_twenty_pack_pins_the_ranked_continuation(self):
        root = Path(__file__).resolve().parents[1]
        pack = load_source_pack(root / "sources/c-top20-v1.toml")

        self.assertEqual(len(pack["source"]), 20)
        self.assertEqual(
            [(row["rank"], row["id"]) for row in pack["source"][10:]],
            [
                (11, "harfbuzz"),
                (12, "freetype"),
                (13, "glib"),
                (14, "expat"),
                (15, "brotli"),
                (16, "libjpeg-turbo"),
                (17, "libunistring"),
                (18, "bzip2"),
                (19, "libtiff"),
                (20, "libpng"),
            ],
        )
        self.assertEqual(pack["study_path"], "coverage/c-top20-width-study.toml")

    def test_status_is_read_only_and_reports_verified_cache(self):
        payload = b"source"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sources/test-pack.toml"
            digest, byte_count = _catalog(path, payload)
            cached = root / "var/fidb-sources/downloads" / digest
            cached.parent.mkdir(parents=True)
            cached.write_bytes(payload)

            result = source_pack_status(root, path)

            self.assertTrue(result["summary"]["ready"])
            self.assertEqual(result["summary"]["download_bytes"], byte_count)
            self.assertEqual(result["sources"][0]["cache"]["state"], "verified-cached")

    def test_pull_uses_only_reviewed_url_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sources/test-pack.toml"
            digest, byte_count = _catalog(path)
            cached = root / "var/fidb-sources/downloads" / digest
            cached.parent.mkdir(parents=True)
            cached.write_bytes(b"source")
            acquisition = AcquisitionResult(
                path=cached,
                sha256=digest,
                bytes=byte_count,
                cache_hit=False,
                attempts=1,
            )
            with patch(
                "fidb_poc.source_packs.acquire_pinned", return_value=acquisition
            ) as acquire:
                result = pull_source_pack(root, path)

            acquire.assert_called_once_with(
                "https://example.invalid/alpha-1.0.tar.gz",
                digest,
                root / "var/fidb-sources/downloads",
            )
            self.assertTrue(result["summary"]["ready"])

    def test_cli_status_does_not_acquire(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _catalog(root / "sources/test-pack.toml")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "source",
                        "status",
                        "test-pack",
                        "--project-root",
                        str(root),
                    ]
                )

            self.assertEqual(status, 0)
            document = json.loads(output.getvalue())
            self.assertEqual(document["operation"], "status")
            self.assertFalse(document["summary"]["ready"])
            self.assertFalse((root / "var").exists())

    def test_unknown_source_id_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "sources/test-pack.toml"
            _catalog(path)
            with self.assertRaisesRegex(ValueError, "unknown reviewed source id"):
                source_pack_status(root, path, ("missing",))


if __name__ == "__main__":
    unittest.main()
