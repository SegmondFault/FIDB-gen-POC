from __future__ import annotations

import hashlib
import json
import lzma
from pathlib import Path
import tempfile
import unittest

from fidb_poc.source_acquisition import (
    _debian_records,
    _homebrew_records,
    acquisition_status,
    load_acquisition,
    load_acquisition_lock,
)


class SourceAcquisitionTests(unittest.TestCase):
    def test_frozen_c80_lock_covers_every_material_candidate(self):
        root = Path(__file__).resolve().parents[1]

        acquisition = load_acquisition(root, "c80-four-source-n80-v1")
        lock = load_acquisition_lock(root, "c80-four-source-n80-v1")

        self.assertEqual(acquisition["download_workers"], 8)
        self.assertEqual(len(lock["candidate"]), 276)
        self.assertEqual(
            sum(row["status"] == "pinned" for row in lock["candidate"]), 275
        )
        pinned_digests = {
            row["sha256"] for row in lock["candidate"] if row["status"] == "pinned"
        }
        self.assertEqual(len(pinned_digests), 272)
        self.assertEqual(
            [
                (row["rank"], row["candidate_key"])
                for row in lock["candidate"]
                if row["status"] == "unresolved"
            ],
            [(62, "opengl")],
        )
        by_id = {row["candidate_key"]: row for row in lock["candidate"]}
        self.assertEqual(by_id["maven"]["resolver_id"], "debian-sid")
        self.assertNotIn("-bin.", by_id["maven"]["url"])
        self.assertEqual(
            by_id["automake"]["url_rewrite_id"], "gnu-kernel-mirror"
        )
        self.assertEqual(
            by_id["automake"]["registry_url"],
            "https://ftpmirror.gnu.org/gnu/automake/automake-1.18.1.tar.xz",
        )
        self.assertEqual(
            by_id["automake"]["url"],
            "https://mirrors.kernel.org/gnu/automake/automake-1.18.1.tar.xz",
        )

    def test_homebrew_resolver_accepts_checksummed_archives_and_aliases_only(self):
        digest = hashlib.sha256(b"alpha").hexdigest()
        rows = [
            {
                "name": "alpha@1",
                "aliases": ["alpha"],
                "versions": {"stable": "1.2.3"},
                "urls": {
                    "stable": {
                        "url": "https://example.invalid/alpha-1.2.3.tar.gz",
                        "checksum": digest,
                    }
                },
            },
            {
                "name": "vcs-only",
                "aliases": [],
                "versions": {"stable": "1"},
                "urls": {
                    "stable": {
                        "url": "https://example.invalid/vcs-only.git",
                        "checksum": None,
                    }
                },
            },
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "formula.json"
            path.write_text(json.dumps(rows), encoding="utf-8")

            records = _homebrew_records(path)

        self.assertEqual(records["alpha@1"][0]["sha256"], digest)
        self.assertTrue(records["alpha"][0]["metadata_alias"])
        self.assertNotIn("vcs-only", records)

    def test_debian_resolver_selects_final_active_stanza_and_not_signature(self):
        older = "a" * 64
        archive = "b" * 64
        signature = "c" * 64
        metadata = f"""Package: alpha
Version: 1.0-1
Extra-Source-Only: yes
Directory: pool/main/a/alpha
Checksums-Sha256:
 {older} 4 alpha_1.0.orig.tar.xz

Package: alpha
Version: 2.0-1
Directory: pool/main/a/alpha
Checksums-Sha256:
 {archive} 8 alpha_2.0.orig.tar.xz
 {signature} 9 alpha_2.0.orig.tar.xz.asc
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Sources.xz"
            path.write_bytes(lzma.compress(metadata.encode("utf-8")))

            records = _debian_records(path, 1024 * 1024)

        self.assertEqual(records["alpha"][0]["version"], "2.0-1")
        self.assertEqual(records["alpha"][0]["sha256"], archive)
        self.assertEqual(records["alpha"][0]["download_bytes"], 8)

    def test_unresolved_subset_status_is_read_only(self):
        root = Path(__file__).resolve().parents[1]

        status = acquisition_status(
            root, "c80-four-source-n80-v1", requested=("opengl",)
        )

        self.assertEqual(status["summary"]["pinned"], 0)
        self.assertEqual(status["summary"]["unique_pinned_payloads"], 0)
        self.assertEqual(status["summary"]["duplicate_pin_references"], 0)
        self.assertEqual(status["summary"]["unique_observed_cached_bytes"], 0)
        self.assertEqual(status["summary"]["unresolved"], 1)
        self.assertEqual(status["candidates"][0]["cache"]["state"], "not-pinned")


if __name__ == "__main__":
    unittest.main()
