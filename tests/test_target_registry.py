import tempfile
import unittest
from pathlib import Path

from fidb_poc.target_registry import load_targets


class TargetRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def test_repository_registry_records_reviewed_and_observed_targets(self):
        rows = load_targets(self.root / "targets/registry.toml")

        self.assertEqual(len(rows), 24)
        self.assertEqual(
            {row["catalog_state"] for row in rows},
            {
                "reviewed-route",
                "reviewed-abi",
                "study-observed",
                "coverage-intent",
            },
        )
        self.assertEqual(
            {(row["platform"], row["binary_format"]) for row in rows},
            {
                ("android", "ELF"),
                ("ios", "Mach-O"),
                ("linux", "ELF"),
                ("macos", "Mach-O"),
                ("windows", "PE/COFF"),
            },
        )

        android = [row for row in rows if row["platform"] == "android"]
        self.assertEqual(len(android), 4)
        self.assertTrue(all(row["catalog_state"] == "coverage-intent" for row in android))
        self.assertTrue(
            {"linux-sparc32-be-elf", "linux-riscv64-elf", "linux-loongarch64-elf"}
            <= {row["id"] for row in rows}
        )

    def test_unknown_fields_and_duplicate_ids_fail_closed(self):
        document = """\
schema_version = "fidb-targets/v1"
[[target]]
id = "duplicate"
label = "First"
platform = "linux"
architecture = "x86_64"
machine = "x86-64"
binary_format = "ELF"
endianness = "little"
bits = 64
catalog_state = "reviewed-route"
evidence = ["worker.toml"]
[[target]]
id = "duplicate"
label = "Second"
platform = "linux"
architecture = "x86_64"
machine = "x86-64"
binary_format = "ELF"
endianness = "little"
bits = 64
catalog_state = "reviewed-route"
evidence = ["worker.toml"]
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.toml"
            path.write_text(document, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_targets(path)


if __name__ == "__main__":
    unittest.main()
