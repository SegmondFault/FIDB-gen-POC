import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fidb_poc.corpus_hash_index import (
    inspect_corpus_hash_index,
    load_corpus_hash_authority,
    update_corpus_hash_index,
)
from fidb_poc.machine_validation_hashes import _create_evidence


class CorpusHashIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "validation").mkdir()
        shutil.copy2(
            self.source / "validation/corpus-hash-index.toml",
            self.root / "validation/corpus-hash-index.toml",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def evidence(
        self,
        name: str,
        *,
        owner: str,
        source_digest: str,
        shared: bool,
        internal_fp: int,
        internal_tn: int,
    ) -> Path:
        path = self.root / f"{name}.sqlite3"
        connection = _create_evidence(path, name, source_digest)
        signature_rows = [
            ("scope", "lang", "0000000000000001", "0000000000000002", 3, 4),
            (
                "scope",
                "lang",
                "0000000000000003" if shared else "0000000000000005",
                "0000000000000004" if shared else "0000000000000006",
                7,
                8,
            ),
        ]
        for index, signature in enumerate(signature_rows):
            connection.execute(
                "INSERT INTO hash_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *signature,
                    "tp",
                    owner,
                    "route",
                    "treatment",
                    "A",
                    str(index),
                    f"query-{index}",
                    f"reference-{index}",
                    f"{owner}.jsonl",
                ),
            )
            connection.execute(
                "INSERT INTO hash_summary VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *signature,
                    1,
                    internal_fp if index == 0 else 0,
                    0,
                    0,
                    1,
                    internal_fp if index == 0 else 0,
                    1,
                    1,
                    1,
                ),
            )
            connection.execute(
                "INSERT INTO hash_signature_owner VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*signature, owner, 1, 1, 0),
            )
        connection.execute(
            "INSERT INTO unit_result VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                1,
                "route",
                "treatment",
                "A",
                "query.jsonl",
                "0" * 64,
                2,
                2,
                internal_fp,
                internal_tn,
                0,
                0,
            ),
        )
        connection.execute("UPDATE metadata SET value='complete' WHERE key='state'")
        connection.commit()
        connection.close()
        return path

    def test_authority_is_incremental_rebuildable_and_non_mutating(self):
        authority = load_corpus_hash_authority(self.root)

        self.assertEqual(authority["incremental"]["update"], "delta-only")
        self.assertEqual(
            authority["incremental"]["true_negatives"],
            "derive-arithmetically",
        )
        self.assertFalse(authority["safety"]["mutate_lane_databases"])
        self.assertFalse(authority["safety"]["permit_in_place_schema_migration"])
        self.assertEqual(authority["acceleration"]["mode"], "compare")
        self.assertEqual(authority["acceleration"]["publish_from"], "canonical-only")

    def test_two_deltas_update_only_touched_signatures_and_are_idempotent(self):
        first = self.evidence(
            "first",
            owner="one@1",
            source_digest="a" * 64,
            shared=True,
            internal_fp=1,
            internal_tn=5,
        )
        second = self.evidence(
            "second",
            owner="two@1",
            source_digest="b" * 64,
            shared=False,
            internal_fp=0,
            internal_tn=2,
        )

        generation_one = update_corpus_hash_index(
            self.root, first, validation_id="c10", run_id="first"
        )
        generation_two = update_corpus_hash_index(
            self.root, second, validation_id="c20", run_id="second"
        )
        repeated = update_corpus_hash_index(
            self.root, second, validation_id="c20", run_id="second"
        )

        self.assertEqual(generation_one["ordinal"], 1)
        self.assertEqual(generation_two["ordinal"], 2)
        self.assertEqual(repeated["state"], "already-ingested")
        self.assertEqual(generation_two["owners"], 2)
        self.assertEqual(generation_two["signatures"], 3)
        self.assertEqual(generation_two["query_observations"], 4)
        self.assertEqual(generation_two["true_positives"], 4)
        self.assertEqual(generation_two["false_positives"], 3)
        self.assertEqual(generation_two["true_negatives"], 9)
        self.assertEqual(generation_two["false_negatives"], 0)
        status = inspect_corpus_hash_index(self.root)
        self.assertEqual(status["state"], "ready")
        self.assertEqual(
            status["generation"]["generation_digest"],
            generation_two["generation_digest"],
        )

        connection = sqlite3.connect(
            self.root / "artifacts/hash-discrimination/corpus-index-v1.sqlite3"
        )
        try:
            rows = connection.execute("""
                SELECT signature.full_hash, state.distinct_owners,
                       state.cumulative_false_positives
                FROM signature_state AS state
                JOIN signature ON signature.id=state.signature_id
                ORDER BY signature.full_hash
                """).fetchall()
        finally:
            connection.close()
        self.assertEqual(
            rows,
            [
                ("0000000000000001", 2, 3),
                ("0000000000000003", 1, 0),
                ("0000000000000005", 1, 0),
            ],
        )

    def test_repeated_owner_in_a_new_batch_fails_closed(self):
        first = self.evidence(
            "first",
            owner="one@1",
            source_digest="a" * 64,
            shared=True,
            internal_fp=0,
            internal_tn=1,
        )
        second = self.evidence(
            "second",
            owner="one@1",
            source_digest="b" * 64,
            shared=False,
            internal_fp=0,
            internal_tn=1,
        )
        generation = update_corpus_hash_index(
            self.root, first, validation_id="c10", run_id="first"
        )

        with self.assertRaisesRegex(ValueError, "repeats existing owner"):
            update_corpus_hash_index(
                self.root, second, validation_id="c20", run_id="second"
            )
        status = inspect_corpus_hash_index(self.root)
        self.assertEqual(status["generation"]["ordinal"], 1)
        self.assertEqual(
            status["generation"]["generation_digest"],
            generation["generation_digest"],
        )

    def test_ingestion_never_mutates_source_evidence(self):
        source = self.evidence(
            "source",
            owner="one@1",
            source_digest="a" * 64,
            shared=True,
            internal_fp=0,
            internal_tn=1,
        )
        before = hashlib.sha256(source.read_bytes()).hexdigest()

        update_corpus_hash_index(
            self.root, source, validation_id="c10", run_id="source"
        )

        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_failed_first_ingestion_publishes_no_empty_index(self):
        source = self.root / "unsealed.sqlite3"
        connection = _create_evidence(source, "unsealed", "a" * 64)
        connection.close()

        with self.assertRaisesRegex(ValueError, "not sealed"):
            update_corpus_hash_index(
                self.root, source, validation_id="c10", run_id="unsealed"
            )

        index_root = self.root / "artifacts/hash-discrimination"
        self.assertFalse((index_root / "corpus-index-v1.sqlite3").exists())
        self.assertEqual(list(index_root.glob("*.partial")), [])


if __name__ == "__main__":
    unittest.main()
