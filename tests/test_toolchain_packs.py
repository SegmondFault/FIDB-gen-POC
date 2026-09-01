from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from fidb_poc.toolchain_cache import CacheInspection
from fidb_poc.toolchain_packs import (
    load_toolchain_pack_catalog,
    resolve_toolchain_profile,
)


class ToolchainPackAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_cross_validates_complete_top_ten_profile(self):
        catalog = load_toolchain_pack_catalog(self.root)

        self.assertEqual(catalog["schema_version"], "fidb-toolchain-pack-catalog/v1")
        self.assertEqual(catalog["host"], {"system": "linux", "architecture": "x86_64"})
        self.assertEqual(len(catalog["packs"]), 8)
        self.assertEqual(len(catalog["routes"]), 10)
        self.assertEqual(len(catalog["profiles"]), 2)
        self.assertEqual(len(catalog["catalog_digest"]), 64)
        self.assertTrue(all(len(row["sha256"]) == 64 for row in catalog["packs"]))

        profile = next(
            row for row in catalog["profiles"] if row["id"] == "c-top10-linux"
        )
        self.assertEqual(
            profile["route_ids"],
            [
                "linux-x86-64-gcc",
                "macos-arm64-apple-clang",
                "windows-x86-64-msvc",
                "linux-arm32-gcc",
                "linux-aarch64-gcc",
                "linux-mips32-be-gcc",
                "linux-mips32-le-gcc",
                "linux-powerpc32-be-gcc",
                "linux-sh32-gcc",
                "linux-m68k-gcc",
            ],
        )

    def test_profile_plan_reports_sizes_cache_and_external_constraints(self):
        def missing(downloads: Path, digest: str) -> CacheInspection:
            return CacheInspection(path=downloads / digest, state="missing")

        with patch("fidb_poc.toolchain_packs.inspect_cached", side_effect=missing):
            plan = resolve_toolchain_profile(
                self.root,
                "c-top10-linux",
                host_system="linux",
                host_architecture="x86_64",
            )

        self.assertEqual(plan["schema_version"], "fidb-toolchain-profile-plan/v1")
        self.assertEqual(plan["state"], "acquisition-required")
        self.assertTrue(plan["host"]["compatible"])
        self.assertEqual(plan["summary"]["routes"], 10)
        self.assertEqual(plan["summary"]["downloadable_routes"], 8)
        self.assertEqual(plan["summary"]["external_routes"], 2)
        self.assertEqual(plan["summary"]["packs"], 8)
        self.assertEqual(plan["summary"]["download_bytes"], 669_585_280)
        self.assertEqual(plan["summary"]["installed_bytes_estimate"], 2_678_341_120)
        self.assertEqual(plan["recommended_next_action"], "pull")
        self.assertEqual(
            sum(
                row["code"] == "external-worker-required"
                for row in plan["requirements"]
            ),
            2,
        )
        self.assertEqual(
            sum(
                row["code"] == "pack-download-required" for row in plan["requirements"]
            ),
            8,
        )

    def test_verified_downloads_do_not_claim_preparation_or_external_readiness(self):
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

        self.assertEqual(plan["state"], "downloadable-ready-external-required")
        self.assertEqual(plan["summary"]["verified_cached_packs"], 8)
        self.assertEqual(plan["summary"]["remaining_download_bytes"], 0)
        self.assertEqual(plan["recommended_next_action"], "define-external-workers")
        self.assertTrue(
            all(
                row["qualification_state"] == "acquisition-reviewed"
                for row in plan["routes"]
                if row["provisioning"] == "downloadable-pack"
            )
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
