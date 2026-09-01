from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fidb_poc.toolchain_qualification import (
    QualificationError,
    compose_osxcross,
    inspect_composition,
    inspect_qualification,
    qualify_route,
    route_material_digest,
)

ROUTE = {
    "id": "linux-x86-64-gcc",
    "target_id": "linux-x86-64-elf",
    "target_triple": "x86_64-buildroot-linux-gnu",
    "pack_ids": ["pack-one"],
    "input_ids": [],
    "state": "prepared-unqualified",
}
QUALIFICATION = {
    "id": "linux-x86-64-gcc",
    "route_id": "linux-x86-64-gcc",
    "tool_source": "pack",
    "tool_pack_id": "pack-one",
    "driver_pattern": "bin/target-gcc",
    "cxx_driver_pattern": "bin/target-g++",
    "archiver_pattern": "bin/target-ar",
    "version_contains": "14.3.0",
    "smoke_languages": ["c", "cpp"],
    "composition": "none",
}
TARGET = {
    "id": "linux-x86-64-elf",
    "binary_format": "ELF",
    "architecture": "x86_64",
    "bits": 64,
    "endianness": "little",
}


def _pack(tool_root: Path) -> dict[str, object]:
    return {
        "id": "pack-one",
        "sha256": "a" * 64,
        "archive_root": "toolchain",
        "compiler_version": "14.3.0",
        "linker_version": "2.43.1",
        "runtime_version": "2.41",
        "preparation": {"state": "prepared", "root": str(tool_root)},
    }


def _elf_x86_64() -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[18:20] = (62).to_bytes(2, "little")
    return bytes(data)


class _FakeRunner:
    def __init__(self, *, bad_object: bool = False):
        self.commands: list[list[str]] = []
        self.bad_object = bad_object

    def __call__(self, arguments, **_kwargs):
        self.commands.append(list(arguments))
        if arguments[1:] == ["--version"]:
            return subprocess.CompletedProcess(
                arguments, 0, stdout="target-gcc 14.3.0\n", stderr=""
            )
        if arguments[1] == "rcs":
            Path(arguments[2]).write_bytes(b"!<arch>\nqualified")
        else:
            output = Path(arguments[arguments.index("-o") + 1])
            output.write_bytes(b"wrong" if self.bad_object else _elf_x86_64())
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")


class ToolchainQualificationTests(unittest.TestCase):
    def _tools(self, root: Path) -> Path:
        tool_root = root / "prepared/toolchain"
        binary = tool_root / "bin"
        binary.mkdir(parents=True)
        for name in ("target-gcc", "target-g++", "target-ar"):
            path = binary / name
            path.write_text("reviewed tool placeholder\n", encoding="utf-8")
            path.chmod(0o755)
        return tool_root

    def test_fixed_c_cpp_smoke_qualifies_and_is_reusable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_root = self._tools(root)
            pack = _pack(tool_root)
            runner = _FakeRunner()

            first = qualify_route(
                root,
                ROUTE,
                QUALIFICATION,
                TARGET,
                [pack],
                [],
                runner=runner,
            )
            second = qualify_route(
                root,
                ROUTE,
                QUALIFICATION,
                TARGET,
                [pack],
                [],
                runner=_FakeRunner(),
            )

            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(len(runner.commands), 4)
            self.assertEqual(runner.commands[0][1:], ["--version"])
            self.assertIn("-std=c++17", runner.commands[2])
            inspection = inspect_qualification(
                root, ROUTE["id"], first.route_material_digest
            )
            self.assertEqual(inspection.state, "qualified")
            self.assertEqual(inspection.record["objects"][0]["binary_format"], "ELF")
            self.assertEqual(
                (first.path / "libfidb-toolchain-smoke.a").read_bytes()[:8],
                b"!<arch>\n",
            )

    def test_wrong_target_object_never_publishes_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = _pack(self._tools(root))
            digest = route_material_digest(ROUTE, QUALIFICATION, [pack], [])

            with self.assertRaisesRegex(QualificationError, "not ELF"):
                qualify_route(
                    root,
                    ROUTE,
                    QUALIFICATION,
                    TARGET,
                    [pack],
                    [],
                    runner=_FakeRunner(bad_object=True),
                )

            self.assertEqual(
                inspect_qualification(root, ROUTE["id"], digest).state, "missing"
            )

    def test_tool_patterns_must_resolve_exactly_once_under_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_root = self._tools(root)
            duplicate = tool_root / "bin/target-gcc-copy"
            duplicate.write_text("duplicate\n", encoding="utf-8")
            duplicate.chmod(0o755)
            qualification = {**QUALIFICATION, "driver_pattern": "bin/target-gcc*"}

            with self.assertRaisesRegex(QualificationError, "exactly once"):
                qualify_route(
                    root,
                    ROUTE,
                    qualification,
                    TARGET,
                    [_pack(tool_root)],
                    [],
                    runner=_FakeRunner(),
                )

    def test_bound_input_material_changes_route_identity(self):
        route = {**ROUTE, "input_ids": ["sdk"]}
        item = {
            "id": "sdk",
            "binding": {
                "state": "bound-verified",
                "document": {
                    "sha256": "b" * 64,
                    "bytes": 10,
                    "metadata": {"sdk_version": "26.0"},
                },
            },
        }
        first = route_material_digest(route, QUALIFICATION, [_pack(Path("/p"))], [item])
        changed = {
            **item,
            "binding": {
                **item["binding"],
                "document": {
                    **item["binding"]["document"],
                    "sha256": "c" * 64,
                },
            },
        }
        second = route_material_digest(
            route, QUALIFICATION, [_pack(Path("/p"))], [changed]
        )
        self.assertNotEqual(first, second)

    def test_qualification_record_tampering_is_broken(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = qualify_route(
                root,
                ROUTE,
                QUALIFICATION,
                TARGET,
                [_pack(self._tools(root))],
                [],
                runner=_FakeRunner(),
            )
            record = result.path / "qualification.json"
            document = json.loads(record.read_text(encoding="utf-8"))
            document["compiler_version_output"] = "tampered"
            record.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                inspect_qualification(
                    root, ROUTE["id"], result.route_material_digest
                ).state,
                "broken",
            )

    def test_osxcross_composition_is_atomic_and_reusable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "prepared/osxcross"
            source_root.mkdir(parents=True)
            build_script = source_root / "build.sh"
            build_script.write_text("#!/bin/sh\n", encoding="utf-8")
            build_script.chmod(0o755)
            llvm_root = root / "prepared/llvm"
            (llvm_root / "bin").mkdir(parents=True)
            sdk = root / "MacOSX26.0.sdk.tar.xz"
            sdk.write_bytes(b"reviewed sdk fixture")
            packs = [
                {
                    "id": "osxcross-source-1",
                    "kind": "source-code",
                    "sha256": "1" * 64,
                    "archive_root": "osxcross",
                    "compiler_version": "source",
                    "linker_version": "source",
                    "runtime_version": "source",
                    "preparation": {"state": "prepared", "root": str(source_root)},
                },
                {
                    "id": "llvm-1",
                    "kind": "compiler-tooling",
                    "sha256": "2" * 64,
                    "archive_root": "llvm",
                    "compiler_version": "22.1.8",
                    "linker_version": "22.1.8",
                    "runtime_version": "22.1.8",
                    "preparation": {"state": "prepared", "root": str(llvm_root)},
                },
            ]
            route = {
                "id": "macos-arm64-osxcross-clang",
                "target_id": "macos-arm64-macho",
                "target_triple": "arm64-apple-darwin",
                "pack_ids": ["osxcross-source-1", "llvm-1"],
                "input_ids": ["apple-macos-sdk"],
                "state": "prepared-unqualified",
            }
            qualification = {
                "route_id": route["id"],
                "tool_source": "composed-route",
                "tool_pack_id": "osxcross-composed",
                "driver_pattern": "bin/arm64-apple-darwin*-clang",
                "cxx_driver_pattern": "bin/arm64-apple-darwin*-clang++",
                "archiver_pattern": "bin/arm64-apple-darwin*-ar",
                "version_contains": "22.1.8",
                "smoke_languages": ["c", "cpp"],
                "composition": "osxcross-llvm",
            }
            inputs = [
                {
                    "id": "apple-macos-sdk",
                    "binding": {
                        "state": "bound-verified",
                        "material_path": str(sdk),
                        "document": {
                            "sha256": "3" * 64,
                            "bytes": sdk.stat().st_size,
                            "metadata": {
                                "sdk_version": "26.0",
                                "deployment_target": "15.0",
                                "package_format": "tar-xz",
                            },
                        },
                    },
                }
            ]

            def fake_build(_command, *, cwd, environment, log, timeout_seconds) -> None:
                self.assertEqual(cwd.name, "source")
                self.assertEqual(environment["BUILD_FLAVOR"], "llvm")
                self.assertEqual(timeout_seconds, 3600)
                Path(environment["TARGET_DIR"]).mkdir(parents=True)
                log.write_bytes(b"reviewed osxcross build\n")

            dependencies = [{"name": "fixture", "path": "/bin/true", "available": True}]
            with (
                patch(
                    "fidb_poc.toolchain_qualification.composition_dependencies",
                    return_value=dependencies,
                ),
                patch(
                    "fidb_poc.toolchain_qualification._run_composition",
                    side_effect=fake_build,
                ) as build,
            ):
                first = compose_osxcross(root, route, qualification, packs, inputs)
                second = compose_osxcross(root, route, qualification, packs, inputs)

            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            build.assert_called_once()
            self.assertEqual(
                inspect_composition(
                    root, route["id"], first.route_material_digest
                ).state,
                "composed",
            )


if __name__ == "__main__":
    unittest.main()
