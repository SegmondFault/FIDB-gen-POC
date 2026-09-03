import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from fidb_poc.ecological_validation import (
    compile_ecological_validation,
    import_ecological_binary,
    load_ecological_validation,
    run_ecological_case,
)
from fidb_poc.lane_database import build_lane_database
from fidb_poc.lane_registry import load_lane_registry


def minimal_x86_64_elf() -> bytes:
    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
        0,
    )
    return identity + header


class EcologicalValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copy2(self.source / "pyproject.toml", self.root / "pyproject.toml")
        for name in ("lanes", "targets", "toolchains", "validation"):
            shutil.copytree(self.source / name, self.root / name)

    def tearDown(self):
        self.temporary.cleanup()

    def metadata(self, **changes):
        result = {
            "filename": "held-out.bin",
            "label": "held-out positive",
            "platform_hint": "linux",
            "expected_present": ["openssl@3.5.8"],
            "expected_absent": [],
            "truth_complete": True,
        }
        result.update(changes)
        return result

    def import_case(self, **metadata):
        payload = minimal_x86_64_elf()
        return import_ecological_binary(
            self.root,
            io.BytesIO(payload),
            len(payload),
            self.metadata(**metadata),
        )

    def build_corpus(self):
        registry_path = self.root / "lanes/registry.toml"
        registry = load_lane_registry(
            registry_path, self.root / "targets/registry.toml"
        )
        digest = __import__("hashlib").sha256(registry_path.read_bytes()).hexdigest()
        build_lane_database(
            self.root / "var/fidb-lanes/linux-x86/generation.sqlite3",
            registry=registry,
            lane_id="linux-x86",
            generation_id="linux-x86-test-v1",
            registry_sha256=digest,
            source_run_id="test-run",
            source_run_sha256="1" * 64,
            occurrences=[
                {
                    "sublane_id": "linux-x86-elf64",
                    "library": "openssl",
                    "library_version": "3.5.8",
                    "source_language": "c",
                    "source_url": "https://example.test/openssl.tar.gz",
                    "source_sha256": "2" * 64,
                    "build_id": "openssl-build",
                    "route_id": "linux-x86-64-gcc",
                    "compiler_family": "gcc",
                    "compiler_version": "14.3.0",
                    "compiler_sha256": None,
                    "treatment_id": "baseline_o2",
                    "build_manifest_sha256": "3" * 64,
                    "ghidra_language_id": "x86:LE:64:default",
                    "ghidra_compiler_spec_id": "gcc",
                    "domain_path": "/crypto/a.o",
                    "function_name": "OPENSSL_init_crypto",
                    "full_hash": "0123456789abcdef",
                    "specific_hash": "fedcba9876543210",
                    "specific_hash_additional_size": 4,
                    "code_unit_size": 40,
                }
            ],
            created_at="2026-09-03T00:00:00+00:00",
        )

    def test_seeded_ecological_authority_and_bounded_import(self):
        authority = load_ecological_validation(self.root)
        self.assertTrue(authority["imports"]["never_execute"])
        case = self.import_case()
        self.assertEqual(case["probe"]["target_id"], "linux-x86-64-elf")
        self.assertEqual(case["probe"]["sublane_id"], "linux-x86-elf64")
        self.assertEqual(case["binary"]["bytes"], len(minimal_x86_64_elf()))
        self.assertFalse(case["readiness"]["ready_to_run"])
        self.assertIn("no compatible", case["readiness"]["blockers"][0])
        stored = self.root / case["binary"]["stored_path"]
        self.assertEqual(stored.read_bytes(), minimal_x86_64_elf())
        self.assertFalse(stored.stat().st_mode & 0o111)

    def test_complete_truth_produces_binary_library_confusion_matrix(self):
        case = self.import_case()
        self.build_corpus()
        status = compile_ecological_validation(self.root)
        self.assertTrue(status["cases"][0]["readiness"]["ready_to_run"])

        def export_signatures(_project, _name, _program, output):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "address": "00401000",
                        "function_name": "FUN_00401000",
                        "ghidra_language_id": "x86:LE:64:default",
                        "ghidra_compiler_spec_id": "gcc",
                        "full_hash": "0123456789abcdef",
                        "specific_hash": "fedcba9876543210",
                        "specific_hash_additional_size": 4,
                        "code_unit_size": 40,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return {
                "functions_hashed": 1,
                "language_id": "x86:LE:64:default",
                "compiler_spec_id": "gcc",
            }

        with (
            mock.patch("fidb_poc.pipeline.find_ghidra", return_value=(Path("/fake/headless"), Path("/fake/ghidra"))),
            mock.patch("fidb_poc.pipeline.ghidra_environment", return_value={}),
            mock.patch("fidb_poc.ghidra_fid.ensure_started"),
            mock.patch("fidb_poc.ghidra_fid.analyze_target", return_value=(Path("/fake/project"), "/input.bin")),
            mock.patch("fidb_poc.ghidra_fid.export_program_signatures", side_effect=export_signatures),
        ):
            report = run_ecological_case(self.root, case["case_id"])

        self.assertEqual(report["confusion_matrix"]["true_positives"], 1)
        self.assertEqual(report["confusion_matrix"]["false_negatives"], 0)
        self.assertEqual(report["confusion_matrix"]["false_positives"], 0)
        self.assertEqual(report["metrics"]["matched_libraries"], 1)
        self.assertEqual(report["owner_matches"][0]["owner"], "openssl@3.5.8")

    def test_unlabelled_observation_does_not_invent_confusion_counts(self):
        case = self.import_case(
            expected_present=[], expected_absent=[], truth_complete=False
        )
        self.assertEqual(case["truth"]["expected_present"], [])
        self.assertFalse(case["truth"]["complete"])

