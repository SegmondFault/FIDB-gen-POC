from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc import toolchain_cli
from fidb_poc.toolchain_cache import (
    AcquisitionResult,
    CacheIntegrityError,
    acquire_pinned,
    inspect_cached,
)


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, content_length: int | None = None):
        super().__init__(payload)
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


class ManagedCacheTests(unittest.TestCase):
    def test_acquire_verifies_atomically_and_reuses_cache(self):
        payload = b"reviewed cross toolchain"
        digest = hashlib.sha256(payload).hexdigest()
        calls = []

        def opener(request, *, timeout):
            calls.append((request.full_url, timeout))
            return _Response(payload, len(payload))

        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary) / "downloads"
            first = acquire_pinned(
                "https://example.invalid/toolchain.tar.xz",
                digest,
                downloads,
                opener=opener,
            )
            second = acquire_pinned(
                "https://example.invalid/toolchain.tar.xz",
                digest,
                downloads,
                opener=opener,
            )

            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(first.path.read_bytes(), payload)
            self.assertEqual(first.path.name, digest)
            self.assertEqual(
                calls, [("https://example.invalid/toolchain.tar.xz", 60.0)]
            )
            self.assertFalse(any(downloads.glob("*.part")))
            self.assertEqual(inspect_cached(downloads, digest).state, "verified-cached")

    def test_invalid_existing_payload_is_quarantined(self):
        payload = b"correct"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary) / "downloads"
            downloads.mkdir(parents=True)
            (downloads / digest).write_bytes(b"incorrect")

            result = acquire_pinned(
                "https://example.invalid/pinned.tar.xz",
                digest,
                downloads,
                opener=lambda *_args, **_kwargs: _Response(payload),
            )

            self.assertIsNotNone(result.quarantined)
            assert result.quarantined is not None
            self.assertEqual(result.quarantined.read_bytes(), b"incorrect")
            self.assertEqual(result.path.read_bytes(), payload)

    def test_digest_mismatch_never_installs_payload(self):
        expected = hashlib.sha256(b"expected").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary) / "downloads"
            with self.assertRaises(CacheIntegrityError):
                acquire_pinned(
                    "https://example.invalid/pinned.tar.xz",
                    expected,
                    downloads,
                    opener=lambda *_args, **_kwargs: _Response(b"wrong"),
                )

            self.assertFalse((downloads / expected).exists())
            self.assertFalse(any(downloads.glob("*.part")))

    def test_transient_failure_retries_with_bounded_backoff(self):
        payload = b"eventual bytes"
        digest = hashlib.sha256(payload).hexdigest()
        calls = 0

        def opener(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("temporary network failure")
            return _Response(payload)

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("fidb_poc.toolchain_cache.time.sleep") as sleep,
        ):
            result = acquire_pinned(
                "https://example.invalid/pinned.tar.xz",
                digest,
                Path(temporary) / "downloads",
                opener=opener,
            )

            self.assertEqual(result.attempts, 2)
            sleep.assert_called_once_with(1.0)


class ToolchainCommandTests(unittest.TestCase):
    def test_acquire_resolves_identity_from_registry(self):
        row = {
            "family": "uclibc",
            "version": "2017.05",
            "variant": "powerpc-fixture",
            "toolchain_url": "https://authority.invalid/toolchain.tar.xz",
            "toolchain_sha256": "a" * 64,
        }
        result = AcquisitionResult(
            path=Path("/cache") / ("a" * 64),
            sha256="a" * 64,
            bytes=123,
            cache_hit=False,
            attempts=1,
        )
        output = io.StringIO()
        with (
            patch("fidb_poc.toolchain_cli._rows", return_value=[row]),
            patch(
                "fidb_poc.toolchain_cli.acquire_pinned", return_value=result
            ) as acquire,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                [
                    "acquire",
                    "--project-root",
                    "/project",
                    "--id",
                    "uclibc@2017.05:powerpc-fixture",
                    "--input",
                    "toolchain",
                ]
            )

        self.assertEqual(status, 0)
        acquire.assert_called_once_with(
            row["toolchain_url"],
            row["toolchain_sha256"],
            Path("/project/var/fidb-toolchains/downloads"),
        )
        document = json.loads(output.getvalue())
        self.assertEqual(document["entries"][0]["id"], "uclibc@2017.05:powerpc-fixture")
        self.assertEqual(
            document["entries"][0]["inputs"][0]["source"], "reviewed-registry"
        )

    def test_unknown_identity_fails_without_acquisition(self):
        errors = io.StringIO()
        with (
            patch("fidb_poc.toolchain_cli._rows", return_value=[]),
            patch("fidb_poc.toolchain_cli.acquire_pinned") as acquire,
            contextlib.redirect_stderr(errors),
        ):
            status = toolchain_cli.main(
                ["acquire", "--id", "unknown@1:route", "--input", "toolchain"]
            )

        self.assertEqual(status, 1)
        acquire.assert_not_called()
        self.assertIn("unknown reviewed toolchain identity", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
