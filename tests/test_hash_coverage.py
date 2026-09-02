import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from fidb_poc.hash_coverage import analyze_signature_coverage, load_signatures


class HashCoverageTests(unittest.TestCase):
    def _manifest(
        self,
        root: Path,
        route: str,
        compiler_signatures: list[tuple[str, str]],
    ) -> Path:
        group = root / route
        ledger = group / "artifacts/libs/fid-signatures/cell.jsonl"
        ledger.parent.mkdir(parents=True)
        with ledger.open("w", encoding="utf-8") as stream:
            for index, (full_hash, specific_hash) in enumerate(
                compiler_signatures, start=1
            ):
                stream.write(
                    json.dumps(
                        {
                            "language": "x86:LE:64:default",
                            "full_hash": full_hash,
                            "specific_hash": specific_hash,
                            "specific_hash_additional_size": 1,
                            "code_unit_size": 10 + index,
                            "name": f"function_{index}",
                            "domain_path": f"/{route}.o",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
        manifest = group / "artifacts/libs/fidb_manifest.csv"
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=(
                    "status",
                    "route",
                    "treatment",
                    "fid_signatures_path",
                    "fid_signatures_sha256",
                    "fid_signature_records",
                    "fid_unique_full_hashes",
                    "fid_unique_signatures",
                ),
            )
            writer.writeheader()
            writer.writerow(
                {
                    "status": "complete",
                    "route": route,
                    "treatment": "baseline_o2",
                    "fid_signatures_path": "artifacts/libs/fid-signatures/cell.jsonl",
                    "fid_signatures_sha256": hashlib.sha256(
                        ledger.read_bytes()
                    ).hexdigest(),
                    "fid_signature_records": len(compiler_signatures),
                    "fid_unique_full_hashes": len(compiler_signatures),
                    "fid_unique_signatures": len(compiler_signatures),
                }
            )
        return manifest

    def test_all_function_signatures_are_compared_across_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self._manifest(
                root,
                "gcc-12",
                [("0000000000000001", "1000000000000001"),
                 ("0000000000000002", "1000000000000002")],
            )
            second = self._manifest(
                root,
                "gcc-13",
                [("0000000000000001", "1000000000000001"),
                 ("0000000000000003", "1000000000000003")],
            )
            compilation = {
                "routes": [
                    {
                        "id": "gcc-12",
                        "target_id": "linux-x86-64-elf",
                        "compiler_id": "gcc-12.3.0",
                        "compiler_family": "gcc",
                    },
                    {
                        "id": "gcc-13",
                        "target_id": "linux-x86-64-elf",
                        "compiler_id": "gcc-13.3.0",
                        "compiler_family": "gcc",
                    },
                ]
            }

            result = analyze_signature_coverage([first, second], compilation)

        self.assertEqual(result["totals"]["unique_signatures"], 3)
        self.assertEqual(result["totals"]["cells"], 2)
        self.assertEqual(
            [row["exclusive_signatures"] for row in result["by_compiler"]],
            [1, 1],
        )
        pair = result["pairwise_same_target"][0]
        self.assertEqual(pair["intersection_signatures"], 1)
        self.assertEqual(pair["union_signatures"], 3)
        self.assertAlmostEqual(pair["jaccard"], 1 / 3)

    def test_empty_signature_ledger_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "empty.jsonl"
            path.touch()
            with self.assertRaisesRegex(ValueError, "empty"):
                load_signatures(path)


if __name__ == "__main__":
    unittest.main()
