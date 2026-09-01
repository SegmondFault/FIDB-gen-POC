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


class ToolchainPackAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_cross_validates_complete_top_ten_profile(self):
        catalog = load_toolchain_pack_catalog(self.root)

        self.assertEqual(catalog["schema_version"], "fidb-toolchain-pack-catalog/v2")
        self.assertEqual(catalog["host"], {"system": "linux", "architecture": "x86_64"})
        self.assertEqual(len(catalog["packs"]), 11)
        self.assertEqual(len(catalog["inputs"]), 1)
        self.assertEqual(len(catalog["routes"]), 12)
        self.assertEqual(len(catalog["profiles"]), 3)
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
                "macos-arm64-osxcross-clang",
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

        self.assertEqual(plan["schema_version"], "fidb-toolchain-profile-plan/v2")
        self.assertEqual(plan["state"], "acquisition-required")
        self.assertTrue(plan["host"]["compatible"])
        self.assertEqual(plan["summary"]["routes"], 10)
        self.assertEqual(plan["summary"]["coverage_requirements"], 10)
        self.assertEqual(plan["summary"]["downloadable_routes"], 10)
        self.assertEqual(plan["summary"]["user_input_routes"], 1)
        self.assertEqual(plan["summary"]["external_routes"], 0)
        self.assertEqual(plan["summary"]["primary_routes"], 8)
        self.assertEqual(plan["summary"]["cross_build_routes"], 2)
        self.assertEqual(plan["summary"]["packs"], 11)
        self.assertEqual(plan["summary"]["download_bytes"], 2_692_424_622)
        self.assertEqual(
            plan["summary"]["pack_installed_bytes_estimate"], 10_769_698_488
        )
        self.assertEqual(
            plan["summary"]["route_additional_installed_bytes_estimate"],
            4_294_967_296,
        )
        self.assertEqual(plan["summary"]["installed_bytes_estimate"], 15_064_665_784)
        self.assertEqual(plan["recommended_next_action"], "pull")
        self.assertEqual(
            sum(row["code"] == "user-input-required" for row in plan["requirements"]),
            1,
        )
        self.assertEqual(
            sum(
                row["code"] == "pack-download-required" for row in plan["requirements"]
            ),
            11,
        )

    def test_verified_downloads_do_not_claim_sdk_or_preparation_readiness(self):
        def verified(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(
                path=downloads / digest,
                state="verified-cached",
                bytes=1,
                observed_sha256=digest,
            )

        with patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=verified):
            plan = resolve_toolchain_profile(
                self.root,
                "c-top10-linux",
                host_system="linux",
                host_architecture="x86_64",
            )

        self.assertEqual(plan["state"], "preparation-required")
        self.assertEqual(plan["summary"]["verified_cached_packs"], 11)
        self.assertEqual(plan["summary"]["prepared_packs"], 0)
        self.assertEqual(plan["summary"]["missing_preparations"], 11)
        self.assertEqual(plan["summary"]["remaining_download_bytes"], 0)
        self.assertEqual(plan["recommended_next_action"], "prepare")
        self.assertEqual(
            next(
                row
                for row in plan["routes"]
                if row["id"] == "macos-arm64-osxcross-clang"
            )["state"],
            "preparation-and-input-required",
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
            {"c-canary", "c-top10-linux", "c-top10-reference"},
        )
        self.assertEqual(inspect.call_count, 11)

    def test_reference_profile_keeps_native_compilers_separate(self):
        with patch(
            "fidb_poc.toolchain_packs.inspect_cached",
            return_value=CacheInspection(path=Path("/cache/missing"), state="missing"),
        ):
            plan = resolve_toolchain_profile(self.root, "c-top10-reference")

        self.assertEqual(plan["summary"]["routes"], 12)
        self.assertEqual(plan["summary"]["coverage_requirements"], 10)
        self.assertEqual(plan["summary"]["cross_build_routes"], 2)
        self.assertEqual(plan["summary"]["native_reference_routes"], 2)
        self.assertEqual(plan["summary"]["external_routes"], 2)
        self.assertEqual(
            sum(
                row["code"] == "external-worker-required"
                for row in plan["requirements"]
            ),
            2,
        )

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
