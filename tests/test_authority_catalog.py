import unittest
from pathlib import Path

from fidb_poc.authority_catalog import authority_catalog


class AuthorityCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_projects_every_reviewed_authority(self):
        document = authority_catalog(self.root)

        self.assertEqual(document["schema_version"], "fidb-authority-catalog/v10")
        self.assertEqual(document["performance_profiles"]["default_profile"], "auto")
        self.assertEqual(len(document["performance_profiles"]["profiles"]), 8)
        self.assertEqual(
            len(document["source_digests"]["performance_profiles_sha256"]), 64
        )
        self.assertEqual(len(document["recipes"]), 5)
        self.assertEqual(len(document["targets"]), 24)
        self.assertEqual(len(document["lane_registry"]["lanes"]), 15)
        self.assertEqual(
            {
                row["target_id"]
                for row in next(
                    lane
                    for lane in document["lane_registry"]["lanes"]
                    if lane["id"] == "linux-x86"
                )["sublanes"]
            },
            {"linux-x86-32-elf", "linux-x86-64-elf"},
        )
        self.assertEqual(len(document["source_digests"]["lanes_sha256"]), 64)
        self.assertEqual(len(document["toolchains"]), 41)
        self.assertEqual(len(document["toolchain_pack_catalog"]["packs"]), 31)
        self.assertEqual(len(document["toolchain_pack_catalog"]["inputs"]), 0)
        self.assertEqual(len(document["toolchain_pack_catalog"]["routes"]), 39)
        self.assertEqual(len(document["toolchain_pack_catalog"]["qualifications"]), 37)
        self.assertEqual(len(document["toolchain_pack_catalog"]["profiles"]), 7)
        self.assertEqual(len(document["factors"]), 41)
        self.assertGreater(len(document["factor_variants"]), 30)
        self.assertEqual(len(document["native"]["routes"]), 19)
        self.assertEqual(
            {
                row["id"]
                for row in document["native"]["routes"]
                if row["toolchain_state"] == "qualified"
            },
            {
                "android-arm64-ndk-r27d-clang-api21",
                "android-arm32-ndk-r27d-clang-api21",
                "android-x86-64-ndk-r27d-clang-api21",
                "android-x86-32-ndk-r27d-clang-api21",
                "android-arm64-ndk-r29-clang-api21",
                "android-arm32-ndk-r29-clang-api21",
                "android-x86-64-ndk-r29-clang-api21",
                "android-x86-32-ndk-r29-clang-api21",
                "linux-x86-64-gcc",
                "windows-x86-64-llvm-mingw",
                "linux-arm32-gcc",
                "linux-aarch64-gcc",
                "linux-mips32-be-gcc",
                "linux-mips32-le-gcc",
                "linux-powerpc32-be-gcc",
                "linux-sh32-gcc",
                "linux-m68k-gcc",
            },
        )
        self.assertIn(
            "plans/coverage-baseline.toml",
            {row["path"] for row in document["plans"]},
        )
        self.assertTrue(all(len(row["toml_sha256"]) == 64 for row in document["plans"]))
        self.assertEqual(len(document["authority_digest"]), 64)
        self.assertEqual(len(document["coverage_universe"]["dimensions"]), 7)
        self.assertEqual(len(document["coverage_universe"]["languages"]), 6)
        self.assertEqual(len(document["coverage_universe"]["profiles"]), 16)
        self.assertEqual(
            {row["id"] for row in document["width_compilations"]},
            {"c-android-gap-v1", "c-width-v1", "c-width-v2"},
        )
        width_v1 = next(
            row for row in document["width_compilations"] if row["id"] == "c-width-v1"
        )
        self.assertIsNone(width_v1["freeze"])
        self.assertEqual(
            width_v1["summary"]["feasible_full_path_executions"],
            width_v1["summary"]["qualified_routes"] * 6,
        )
        self.assertEqual(
            document["coverage_universe"]["population"][
                "published_priority_head_families"
            ],
            283,
        )
        campaign_b = next(
            row
            for row in document["coverage_universe"]["scenarios"]
            if row["id"] == "c-campaign-b-four-source-n80"
        )
        self.assertEqual(campaign_b["unique_executions"], 5_094)
        self.assertEqual(campaign_b["replayed_executions"], 10_188)
        self.assertEqual(len(document["width_studies"]), 1)
        width_study = document["width_studies"][0]
        self.assertEqual(width_study["id"], "batch-010")
        self.assertEqual(width_study["readiness"]["reviewed_recipe_families"], 1)
        self.assertEqual(width_study["readiness"]["source_evidence_families"], 10)
        self.assertEqual(width_study["readiness"]["queue_state"], "not-materialized")
        self.assertTrue(width_study["readiness"]["blockers"])
        requirements = width_study["toolchain_requirements"]
        self.assertEqual(len(requirements), 22)
        self.assertEqual(requirements[0]["route_state"], "installed")
        self.assertEqual(requirements[1]["route_state"], "remote-required")
        self.assertEqual(requirements[2]["route_state"], "remote-required")
        self.assertEqual(requirements[7]["route_state"], "installed")
        self.assertEqual(requirements[11]["route_state"], "definition-required")
        self.assertEqual(
            width_study["readiness"]["default_route_state_counts"],
            {
                "installed": 1,
                "pinned-source": 0,
                "archive-only": 0,
                "remote-required": 2,
                "definition-required": 0,
            },
        )
        self.assertEqual(len(document["width_batches"]), 2)
        width_batch = document["width_batches"][0]
        self.assertEqual(width_batch["id"], "batch-020")
        self.assertEqual(width_batch["summary"]["total_executions"], 1_998)
        self.assertEqual(width_batch["readiness"]["source_pins"], 9)
        self.assertEqual(width_batch["readiness"]["recipe_ready_libraries"], 0)
        self.assertEqual(width_batch["readiness"]["blocked_executions"], 1_998)
        android_gap = document["width_batches"][1]
        self.assertEqual(android_gap["id"], "batch-020-android-gap")
        self.assertEqual(android_gap["summary"]["total_executions"], 48)
        self.assertEqual(
            android_gap["readiness"]["queue_state"], "not-materialized-disarmed"
        )

        targets = {row["id"]: row for row in document["targets"]}
        self.assertEqual(
            targets["linux-x86-64-elf"]["native_route_ids"],
            ["linux-x86_64-gnu-gcc", "linux-x86-64-gcc"],
        )
        self.assertEqual(
            len(targets["linux-powerpc32-be-elf"]["source_capable_toolchain_ids"]),
            1,
        )
        self.assertEqual(targets["windows-x86-64-pecoff"]["toolchain_ids"], [])
        self.assertEqual(targets["android-arm64-v8a-elf"]["toolchain_ids"], [])
        self.assertEqual(
            targets["android-arm64-v8a-elf"]["managed_pack_ids"],
            [
                "android-ndk-r27d-linux-x86-64",
                "android-ndk-r29-linux-x86-64",
            ],
        )
        self.assertEqual(len(targets["android-arm64-v8a-elf"]["managed_route_ids"]), 2)
        self.assertEqual(targets["linux-riscv64-elf"]["toolchain_ids"], [])

    def test_catalog_contains_no_caller_supplied_command_field(self):
        document = authority_catalog(self.root)

        def visit(value: object) -> None:
            if isinstance(value, dict):
                self.assertNotIn("command", value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(document)


if __name__ == "__main__":
    unittest.main()
