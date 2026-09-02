from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from fidb_poc.toolchain_cache import CacheInspection
from fidb_poc.toolchain_packs import (
    load_toolchain_pack_catalog,
    resolve_toolchain_profile,
    resolve_toolchain_profiles,
)
from fidb_poc.toolchain_prepare import PreparationInspection
from fidb_poc.toolchain_qualification import QualificationInspection


class ToolchainPackAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_cross_validates_complete_top_ten_profile(self):
        catalog = load_toolchain_pack_catalog(self.root)

        self.assertEqual(catalog["schema_version"], "fidb-toolchain-pack-catalog/v4")
        self.assertGreaterEqual(len(catalog["compilers"]), 10)
        self.assertEqual(catalog["host"], {"system": "linux", "architecture": "x86_64"})
        self.assertEqual(len(catalog["packs"]), 31)
        self.assertEqual(len(catalog["inputs"]), 0)
        self.assertEqual(len(catalog["routes"]), 39)
        self.assertEqual(len(catalog["qualifications"]), 37)
        self.assertEqual(len(catalog["profiles"]), 7)
        self.assertEqual(len(catalog["catalog_digest"]), 64)
        self.assertTrue(all(len(row["sha256"]) == 64 for row in catalog["packs"]))

        profile = next(
            row for row in catalog["profiles"] if row["id"] == "c-top10-linux"
        )
        self.assertEqual(profile["language_id"], "c")
        self.assertEqual(
            profile["route_ids"],
            [
                "linux-x86-64-gcc",
                "macos-arm64-apple-clang",
                "windows-x86-64-llvm-mingw",
                "linux-arm32-gcc",
                "linux-aarch64-gcc",
                "linux-mips32-be-gcc",
                "linux-mips32-le-gcc",
                "linux-powerpc32-be-gcc",
                "linux-sh32-gcc",
                "linux-m68k-gcc",
            ],
        )

    def test_profile_plan_reports_sizes_cache_and_user_input_constraint(self):
        def missing(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(path=downloads / digest, state="missing")

        with patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=missing):
            plan = resolve_toolchain_profile(
                self.root,
                "c-top10-linux",
                host_system="linux",
                host_architecture="x86_64",
            )

        self.assertEqual(plan["schema_version"], "fidb-toolchain-profile-plan/v3")
        self.assertEqual(plan["state"], "acquisition-required")
        self.assertTrue(plan["host"]["compatible"])
        self.assertEqual(plan["summary"]["routes"], 10)
        self.assertEqual(plan["summary"]["coverage_requirements"], 10)
        self.assertEqual(plan["summary"]["downloadable_routes"], 9)
        self.assertEqual(plan["summary"]["user_input_routes"], 0)
        self.assertEqual(plan["summary"]["external_routes"], 1)
        self.assertEqual(plan["summary"]["primary_routes"], 9)
        self.assertEqual(plan["summary"]["cross_build_routes"], 1)
        self.assertEqual(plan["summary"]["packs"], 9)
        self.assertEqual(plan["summary"]["download_bytes"], 753_465_840)
        self.assertEqual(
            plan["summary"]["pack_installed_bytes_estimate"], 3_852_132_920
        )
        self.assertEqual(
            plan["summary"]["route_additional_installed_bytes_estimate"],
            0,
        )
        self.assertEqual(plan["summary"]["installed_bytes_estimate"], 3_852_132_920)
        self.assertEqual(
            plan["summary"]["installed_size_evidence"],
            "measured-preparation-2026-09-02",
        )
        self.assertEqual(plan["recommended_next_action"], "pull")
        self.assertEqual(
            sum(
                row["code"] == "external-worker-required"
                for row in plan["requirements"]
            ),
            1,
        )
        self.assertEqual(
            sum(
                row["code"] == "pack-download-required" for row in plan["requirements"]
            ),
            9,
        )

    def test_verified_downloads_do_not_claim_sdk_or_preparation_readiness(self):
        def verified(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(
                path=downloads / digest,
                state="verified-cached",
                bytes=1,
                observed_sha256=digest,
            )

        def missing_preparation(directory: Path, digest: str, archive_root: str):
            return PreparationInspection(
                path=directory / digest,
                root=directory / digest / archive_root,
                state="missing",
            )

        with (
            patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=verified),
            patch(
                "fidb_poc.toolchain_packs.inspect_prepared",
                side_effect=missing_preparation,
            ),
        ):
            plan = resolve_toolchain_profile(
                self.root,
                "c-top10-linux",
                host_system="linux",
                host_architecture="x86_64",
            )

        self.assertEqual(plan["state"], "preparation-required")
        self.assertEqual(plan["summary"]["verified_cached_packs"], 9)
        self.assertEqual(plan["summary"]["prepared_packs"], 0)
        self.assertEqual(plan["summary"]["missing_preparations"], 9)
        self.assertEqual(plan["summary"]["remaining_download_bytes"], 0)
        self.assertEqual(plan["recommended_next_action"], "prepare")
        self.assertEqual(
            next(
                row for row in plan["routes"] if row["id"] == "macos-arm64-apple-clang"
            )["state"],
            "external-required",
        )
        self.assertTrue(
            all(
                row["qualification_state"] == "acquisition-reviewed"
                for row in plan["routes"]
                if row["provisioning"] == "downloadable-pack"
            )
        )

    def test_profile_digest_does_not_depend_on_local_cache_state(self):
        with patch(
            "fidb_poc.toolchain_packs.inspect_cached",
            return_value=CacheInspection(path=Path("/cache/missing"), state="missing"),
        ):
            missing = resolve_toolchain_profile(self.root, "c-canary")
        with patch(
            "fidb_poc.toolchain_packs.inspect_cached",
            side_effect=lambda downloads, digest: CacheInspection(
                path=downloads / digest,
                state="verified-cached",
                bytes=1,
                observed_sha256=digest,
            ),
        ):
            verified = resolve_toolchain_profile(self.root, "c-canary")

        self.assertEqual(missing["profile_digest"], verified["profile_digest"])

    def test_all_profiles_share_one_cache_inspection_per_digest(self):
        def missing(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(path=downloads / digest, state="missing")

        with patch(
            "fidb_poc.toolchain_packs.inspect_cached", side_effect=missing
        ) as inspect:
            plans = resolve_toolchain_profiles(self.root)

        self.assertEqual(
            {row["profile"]["id"] for row in plans},
            {
                "c-canary",
                "c-android-width-v1",
                "c-compiler-width-v1",
                "c-nonapple-baseline-v1",
                "c-nonapple-width-v2",
                "c-top10-linux",
                "c-top10-reference",
            },
        )
        self.assertEqual(inspect.call_count, 31)

    def test_reference_profile_keeps_native_compilers_separate(self):
        with patch(
            "fidb_poc.toolchain_packs.inspect_cached",
            return_value=CacheInspection(path=Path("/cache/missing"), state="missing"),
        ):
            plan = resolve_toolchain_profile(self.root, "c-top10-reference")

        self.assertEqual(plan["summary"]["routes"], 11)
        self.assertEqual(plan["summary"]["coverage_requirements"], 10)
        self.assertEqual(plan["summary"]["cross_build_routes"], 1)
        self.assertEqual(plan["summary"]["native_reference_routes"], 1)
        self.assertEqual(plan["summary"]["external_routes"], 2)
        self.assertEqual(
            sum(
                row["code"] == "external-worker-required"
                for row in plan["requirements"]
            ),
            2,
        )

    def test_android_width_shares_two_ndks_across_four_abis(self):
        catalog = load_toolchain_pack_catalog(self.root)
        profile = next(
            row for row in catalog["profiles"] if row["id"] == "c-android-width-v1"
        )
        routes = {
            row["id"]: row
            for row in catalog["routes"]
            if row["id"] in profile["route_ids"]
        }

        self.assertEqual(len(routes), 8)
        self.assertEqual(
            {row["target_id"] for row in routes.values()},
            {
                "android-arm64-v8a-elf",
                "android-armeabi-v7a-elf",
                "android-x86-64-elf",
                "android-x86-32-elf",
            },
        )
        self.assertEqual(
            {pack_id for row in routes.values() for pack_id in row["pack_ids"]},
            {
                "android-ndk-r27d-linux-x86-64",
                "android-ndk-r29-linux-x86-64",
            },
        )
        self.assertEqual(
            {row["target_triple"][-2:] for row in routes.values()}, {"21"}
        )
    def test_ready_material_advances_through_qualification_then_external_worker(self):
        def cached(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(
                path=downloads / digest,
                state="verified-cached",
                bytes=1,
                observed_sha256=digest,
            )

        def prepared(directory: Path, digest: str, archive_root: str):
            path = directory / digest
            return PreparationInspection(
                path=path,
                root=path / archive_root,
                state="prepared",
                manifest={"archive_root": archive_root},
            )

        with (
            patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=cached),
            patch("fidb_poc.toolchain_packs.inspect_prepared", side_effect=prepared),
            patch(
                "fidb_poc.toolchain_packs.inspect_qualification",
                return_value=QualificationInspection(Path("/qualified"), "missing"),
            ),
        ):
            qualification_required = resolve_toolchain_profile(
                self.root, "c-top10-linux"
            )

        self.assertEqual(qualification_required["state"], "qualification-required")
        self.assertEqual(qualification_required["summary"]["composed_routes"], 0)
        self.assertEqual(qualification_required["summary"]["missing_qualifications"], 9)
        self.assertEqual(qualification_required["recommended_next_action"], "qualify")

        with (
            patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=cached),
            patch("fidb_poc.toolchain_packs.inspect_prepared", side_effect=prepared),
            patch(
                "fidb_poc.toolchain_packs.inspect_qualification",
                return_value=QualificationInspection(
                    Path("/qualified"), "qualified", {"record_digest": "a" * 64}
                ),
            ),
        ):
            qualified = resolve_toolchain_profile(self.root, "c-top10-linux")

        self.assertEqual(qualified["state"], "qualified-external-required")
        self.assertEqual(qualified["summary"]["qualified_routes"], 9)
        self.assertEqual(qualified["recommended_next_action"], "start-external-workers")

    def test_incompatible_host_is_a_structured_blocker(self):
        with patch(
            "fidb_poc.toolchain_packs.inspect_cached",
            return_value=CacheInspection(path=Path("/cache/missing"), state="missing"),
        ):
            plan = resolve_toolchain_profile(
                self.root,
                "c-canary",
                host_system="darwin",
                host_architecture="arm64",
            )

        self.assertEqual(plan["state"], "blocked")
        self.assertFalse(plan["host"]["compatible"])
        self.assertEqual(plan["requirements"][0]["code"], "host-incompatible")
        self.assertEqual(plan["recommended_next_action"], "use-compatible-host")

    def test_unknown_profile_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown toolchain profile"):
            resolve_toolchain_profile(self.root, "not-reviewed")


if __name__ == "__main__":
    unittest.main()
