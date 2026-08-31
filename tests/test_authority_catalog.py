import unittest
from pathlib import Path

from fidb_poc.authority_catalog import authority_catalog


class AuthorityCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_catalog_projects_every_reviewed_authority(self):
        document = authority_catalog(self.root)

        self.assertEqual(document["schema_version"], "fidb-authority-catalog/v2")
        self.assertEqual(len(document["recipes"]), 4)
        self.assertEqual(len(document["targets"]), 11)
        self.assertEqual(len(document["toolchains"]), 41)
        self.assertEqual(len(document["factors"]), 41)
        self.assertGreater(len(document["factor_variants"]), 30)
        self.assertEqual(
            {row["id"] for row in document["native"]["routes"]},
            {"linux-x86_64-gnu-gcc"},
        )
        self.assertIn(
            "plans/coverage-baseline.toml",
            {row["path"] for row in document["plans"]},
        )
        self.assertTrue(all(len(row["toml_sha256"]) == 64 for row in document["plans"]))
        self.assertEqual(len(document["authority_digest"]), 64)

        targets = {row["id"]: row for row in document["targets"]}
        self.assertEqual(
            targets["linux-x86-64-elf"]["native_route_ids"],
            ["linux-x86_64-gnu-gcc"],
        )
        self.assertEqual(
            len(targets["linux-powerpc32-be-elf"]["source_capable_toolchain_ids"]),
            1,
        )
        self.assertEqual(
            targets["windows-x86-64-pecoff"]["toolchain_ids"], []
        )

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
