import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc.lane_registry import (
    load_lane_registry,
    resolve_program_sublanes,
    resolve_target_sublane,
)


class LaneRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_repository_registry_groups_user_visible_platform_families(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        lanes = {row["id"]: row for row in registry["lanes"]}
        self.assertEqual(registry["schema_version"], "fidb-lanes/v1")
        self.assertEqual(
            {row["target_id"] for row in lanes["linux-x86"]["sublanes"]},
            {"linux-x86-32-elf", "linux-x86-64-elf"},
        )
        self.assertEqual(
            {row["target_id"] for row in lanes["windows-x86"]["sublanes"]},
            {"windows-x86-32-pecoff", "windows-x86-64-pecoff"},
        )
        self.assertEqual(
            {row["target_id"] for row in lanes["android-arm"]["sublanes"]},
            {"android-armeabi-v7a-elf", "android-arm64-v8a-elf"},
        )
        self.assertEqual(
            {row["target_id"] for row in lanes["ios-arm"]["sublanes"]},
            {"ios-armv7-macho", "ios-arm64-macho"},
        )
        self.assertTrue(all(row["state"] == "experimental" for row in lanes.values()))

    def test_target_resolution_returns_broad_lane_and_exact_sublane(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        lane, sublane = resolve_target_sublane(registry, "linux-x86-64-elf")

        self.assertEqual(lane["id"], "linux-x86")
        self.assertEqual(sublane["id"], "linux-x86-elf64")
        self.assertEqual(sublane["target"]["bits"], 64)
        self.assertEqual(sublane["ghidra_language_ids"], ["x86:LE:64:default"])

    def test_unknown_target_and_open_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(self.root / "targets/registry.toml", root / "targets.toml")
            source = (self.root / "lanes/registry.toml").read_text(encoding="utf-8")
            path = root / "lanes.toml"
            path.write_text(
                source.replace(
                    'target_id = "linux-x86-32-elf"',
                    'target_id = "not-a-target"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown target"):
                load_lane_registry(path, root / "targets.toml")

            path.write_text(source + "\nunexpected = true\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown"):
                load_lane_registry(path, root / "targets.toml")

    def test_inspected_program_facts_resolve_without_user_architecture_choice(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        result = resolve_program_sublanes(
            registry,
            platform="linux",
            binary_format="ELF",
            machine="x86-64",
            bits=64,
            endianness="little",
            ghidra_language_id="x86:LE:64:default",
            compiler_spec_id="gcc",
        )

        self.assertEqual(result["state"], "exact")
        self.assertEqual(result["candidates"][0]["lane_id"], "linux-x86")
        self.assertEqual(result["candidates"][0]["sublane_id"], "linux-x86-elf64")

    def test_partial_program_facts_report_ambiguity_instead_of_guessing(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        result = resolve_program_sublanes(
            registry,
            platform="linux",
            binary_format="ELF",
            endianness="little",
        )

        self.assertEqual(result["state"], "ambiguous")
        self.assertGreater(len(result["candidates"]), 1)
        self.assertIn(
            "linux-x86",
            {row["lane_id"] for row in result["candidates"]},
        )

    def test_resolution_can_exclude_unresolved_coverage_intent(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        result = resolve_program_sublanes(
            registry,
            platform="linux",
            architecture="riscv64",
            include_unresolved=False,
        )

        self.assertEqual(result["state"], "unsupported")
        self.assertEqual(result["candidates"], [])

    def test_resolution_requires_real_program_evidence(self):
        registry = load_lane_registry(
            self.root / "lanes/registry.toml",
            self.root / "targets/registry.toml",
        )

        with self.assertRaisesRegex(ValueError, "at least one inspected"):
            resolve_program_sublanes(registry)


if __name__ == "__main__":
    unittest.main()
