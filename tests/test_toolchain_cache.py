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
from fidb_poc.toolchain_prepare import PreparationResult
from fidb_poc.toolchain_inputs import InputBindingResult
from fidb_poc.toolchain_qualification import (
    CompositionResult,
    QualificationResult,
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

    def test_profile_plan_is_read_only_json(self):
        plan = {
            "schema_version": "fidb-toolchain-profile-plan/v3",
            "operation": "status",
            "profile": {"id": "c-canary"},
            "host": {"compatible": True},
            "packs": [],
        }
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                return_value=plan,
            ) as resolve,
            patch("fidb_poc.toolchain_cli.acquire_pinned") as acquire,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                [
                    "profile",
                    "plan",
                    "c-canary",
                    "--project-root",
                    "/project",
                ]
            )

        self.assertEqual(status, 0)
        resolve.assert_called_once_with(Path("/project"), "c-canary")
        acquire.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["operation"], "plan")

    def test_profile_pull_acquires_only_resolved_packs(self):
        pack = {
            "id": "pack-one",
            "url": "https://authority.invalid/pack.tar.xz",
            "sha256": "b" * 64,
            "download_bytes": 123,
        }
        before = {
            "host": {
                "compatible": True,
                "required_system": "linux",
                "required_architecture": "x86_64",
            },
            "packs": [pack],
        }
        after = {"state": "verified-cached", "host": {"compatible": True}}
        acquisition = AcquisitionResult(
            path=Path("/project/var/fidb-toolchains/downloads") / ("b" * 64),
            sha256="b" * 64,
            bytes=123,
            cache_hit=False,
            attempts=1,
        )
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                side_effect=[before, after],
            ) as resolve,
            patch(
                "fidb_poc.toolchain_cli.acquire_pinned", return_value=acquisition
            ) as acquire,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                [
                    "profile",
                    "pull",
                    "c-canary",
                    "--project-root",
                    "/project",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(resolve.call_count, 2)
        acquire.assert_called_once_with(
            pack["url"],
            pack["sha256"],
            Path("/project/var/fidb-toolchains/downloads"),
        )
        document = json.loads(output.getvalue())
        self.assertEqual(document["operation"], "pull")
        self.assertEqual(document["acquisitions"][0]["pack_id"], "pack-one")

    def test_profile_pull_refuses_incompatible_host(self):
        before = {
            "host": {
                "compatible": False,
                "required_system": "linux",
                "required_architecture": "x86_64",
            },
            "packs": [],
        }
        errors = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                return_value=before,
            ),
            patch("fidb_poc.toolchain_cli.acquire_pinned") as acquire,
            contextlib.redirect_stderr(errors),
        ):
            status = toolchain_cli.main(["profile", "pull", "c-canary"])

        self.assertEqual(status, 1)
        acquire.assert_not_called()
        self.assertIn(
            "refusing profile pull on an incompatible host", errors.getvalue()
        )

    def test_profile_prepare_extracts_only_verified_resolved_packs(self):
        archive = Path("/project/var/fidb-toolchains/downloads") / ("c" * 64)
        pack = {
            "id": "pack-one",
            "sha256": "c" * 64,
            "download_bytes": 123,
            "installed_bytes_estimate": 400,
            "archive_root": "toolchain",
            "state": "verified-cached",
            "cache": {"path": str(archive)},
        }
        before = {
            "host": {
                "compatible": True,
                "required_system": "linux",
                "required_architecture": "x86_64",
            },
            "packs": [pack],
        }
        after = {"state": "prepared-unqualified", "host": {"compatible": True}}
        preparation = PreparationResult(
            path=Path("/project/var/fidb-toolchains/prepared") / ("c" * 64),
            root=Path("/project/var/fidb-toolchains/prepared")
            / ("c" * 64)
            / "toolchain",
            archive_sha256="c" * 64,
            archive_bytes=123,
            extracted_bytes=300,
            members=3,
            files=2,
            directories=1,
            symlinks=0,
            cache_hit=False,
        )
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                side_effect=[before, after],
            ),
            patch(
                "fidb_poc.toolchain_cli.prepare_pinned_archive",
                return_value=preparation,
            ) as prepare,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                [
                    "profile",
                    "prepare",
                    "c-canary",
                    "--project-root",
                    "/project",
                ]
            )

        self.assertEqual(status, 0)
        prepare.assert_called_once_with(
            archive,
            "c" * 64,
            123,
            "toolchain",
            Path("/project/var/fidb-toolchains/prepared"),
            max_extracted_bytes=984,
        )
        document = json.loads(output.getvalue())
        self.assertEqual(document["operation"], "prepare")
        self.assertEqual(document["preparations"][0]["pack_id"], "pack-one")

    def test_profile_compose_uses_only_reviewed_composed_routes(self):
        definition = {"composition": "osxcross-llvm"}
        route = {
            "id": "macos-arm64-osxcross-clang",
            "state": "composition-required",
            "qualification": {"definition": definition},
        }
        before = {
            "host": {
                "compatible": True,
                "required_system": "linux",
                "required_architecture": "x86_64",
            },
            "routes": [route],
            "packs": [{"id": "llvm"}],
            "inputs": [{"id": "apple-macos-sdk"}],
        }
        after = {"state": "qualification-required", "host": {"compatible": True}}
        result = CompositionResult(
            path=Path("/project/var/fidb-toolchains/composed/route/digest"),
            root=Path("/project/var/fidb-toolchains/composed/route/digest/toolchain"),
            route_id=route["id"],
            route_material_digest="a" * 64,
            log_sha256="b" * 64,
            log_bytes=123,
            cache_hit=False,
        )
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                side_effect=[before, after],
            ),
            patch(
                "fidb_poc.toolchain_cli.compose_osxcross", return_value=result
            ) as compose,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                ["profile", "compose", "c-top10-linux", "--project-root", "/project"]
            )

        self.assertEqual(status, 0)
        compose.assert_called_once_with(
            Path("/project"),
            route,
            definition,
            before["packs"],
            before["inputs"],
        )
        self.assertEqual(json.loads(output.getvalue())["operation"], "compose")

    def test_profile_qualify_runs_fixed_smoke_for_every_ready_host_route(self):
        definition = {"composition": "none"}
        route = {
            "id": "linux-x86-64-gcc",
            "target_id": "linux-x86-64-elf",
            "provisioning": "downloadable-pack",
            "state": "qualification-required",
            "qualification": {"definition": definition},
        }
        before = {
            "host": {
                "compatible": True,
                "required_system": "linux",
                "required_architecture": "x86_64",
            },
            "routes": [route],
            "packs": [{"id": "gcc"}],
            "inputs": [],
        }
        after = {"state": "qualified", "host": {"compatible": True}}
        target = {"id": "linux-x86-64-elf"}
        result = QualificationResult(
            path=Path("/project/var/fidb-toolchains/qualified/route/digest"),
            route_id=route["id"],
            route_material_digest="a" * 64,
            record_digest="b" * 64,
            cache_hit=False,
        )
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.resolve_toolchain_profile",
                side_effect=[before, after],
            ),
            patch("fidb_poc.toolchain_cli.load_targets", return_value=[target]),
            patch(
                "fidb_poc.toolchain_cli.qualify_route", return_value=result
            ) as qualify,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                ["profile", "qualify", "c-canary", "--project-root", "/project"]
            )

        self.assertEqual(status, 0)
        qualify.assert_called_once_with(
            Path("/project"),
            route,
            definition,
            target,
            before["packs"],
            before["inputs"],
        )
        self.assertEqual(json.loads(output.getvalue())["operation"], "qualify")

    def test_profile_wrappers_are_executable_and_default_to_top_ten(self):
        project_root = Path(__file__).resolve().parents[1]
        for operation in ("plan", "status", "pull", "prepare", "compose", "qualify"):
            path = project_root / f"scripts/toolchains/{operation}.sh"
            self.assertTrue(path.stat().st_mode & 0o111)
            source = path.read_text(encoding="utf-8")
            self.assertIn("profile=${1:-c-top10-linux}", source)
            self.assertIn(f"toolchain profile {operation}", source)

    def test_input_bind_resolves_authority_and_passes_exact_metadata(self):
        authority = {
            "id": "apple-macos-sdk",
            "kind": "user-supplied-sdk",
            "target_ids": ["macos-arm64-macho"],
            "authority": "https://authority.invalid/sdk",
            "required_metadata": ["sdk_version", "sha256", "bytes"],
        }
        binding = InputBindingResult(
            input_id="apple-macos-sdk",
            binding_path=Path(
                "/project/var/fidb-toolchains/bindings/apple-macos-sdk.json"
            ),
            material_path=Path("/project/var/fidb-toolchains/inputs") / ("d" * 64),
            sha256="d" * 64,
            bytes=123,
            metadata={"sdk_version": "26.0", "sha256": "d" * 64, "bytes": "123"},
            material_cache_hit=False,
        )
        output = io.StringIO()
        with (
            patch(
                "fidb_poc.toolchain_cli.load_toolchain_pack_catalog",
                return_value={"inputs": [authority]},
            ),
            patch("fidb_poc.toolchain_cli.bind_input", return_value=binding) as bind,
            contextlib.redirect_stdout(output),
        ):
            status = toolchain_cli.main(
                [
                    "input",
                    "bind",
                    "apple-macos-sdk",
                    "--project-root",
                    "/project",
                    "--path",
                    "/tmp/MacOSX.sdk.tar.xz",
                    "--sha256",
                    "d" * 64,
                    "--bytes",
                    "123",
                    "--metadata",
                    "sdk_version=26.0",
                    "--metadata",
                    f"sha256={'d' * 64}",
                    "--metadata",
                    "bytes=123",
                ]
            )

        self.assertEqual(status, 0)
        bind.assert_called_once_with(
            Path("/project"),
            authority,
            Path("/tmp/MacOSX.sdk.tar.xz"),
            "d" * 64,
            123,
            {"sdk_version": "26.0", "sha256": "d" * 64, "bytes": "123"},
        )
        self.assertEqual(json.loads(output.getvalue())["operation"], "bind")

    def test_macos_worker_wrappers_are_typed_and_executable(self):
        project_root = Path(__file__).resolve().parents[1]
        for name in ("macos-preflight.sh", "macos-run.sh"):
            path = project_root / "scripts/workers" / name
            self.assertTrue(path.stat().st_mode & 0o111)
            source = path.read_text(encoding="utf-8")
            self.assertIn("macos-arm64-apple-clang", source)
            self.assertNotIn("eval", source)


if __name__ == "__main__":
    unittest.main()
