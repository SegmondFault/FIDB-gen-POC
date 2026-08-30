import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from fidb_poc.plan_drafts import (
    DraftConflictError,
    resolve_plan_draft,
    save_plan_draft,
)


class PlanDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("worker.json", "pyproject.toml"):
            shutil.copy2(self.source_root / name, self.root / name)
        for name in ("plans", "recipes", "sensitivity", "toolchains"):
            shutil.copytree(self.source_root / name, self.root / name)
        self.toml = (self.root / "plans/bzip2-native.toml").read_text(encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_resolve_does_not_retain_the_draft(self):
        result = resolve_plan_draft(self.toml, self.root)

        self.assertEqual(result["schema_version"], "fidb-plan-draft-resolution/v1")
        self.assertEqual(result["resolved"]["summary"]["planned_cells"], 1)
        self.assertFalse((self.root / "plans/drafts").exists())

    def test_save_is_atomic_and_updates_only_with_matching_digest(self):
        created = save_plan_draft("bzip2-native-baseline", self.toml, self.root)
        destination = self.root / created["path"]
        self.assertEqual(destination.read_text(encoding="utf-8"), self.toml)

        with self.assertRaises(DraftConflictError):
            save_plan_draft("bzip2-native-baseline", self.toml, self.root)

        expected = hashlib.sha256(destination.read_bytes()).hexdigest()
        updated = save_plan_draft(
            "bzip2-native-baseline",
            self.toml,
            self.root,
            expected_sha256=expected,
        )
        self.assertEqual(updated["previous_sha256"], expected)
        self.assertFalse(
            (destination.parent / ".bzip2-native-baseline.toml.tmp").exists()
        )

    def test_invalid_name_and_raw_command_fail_without_writing(self):
        with self.assertRaisesRegex(ValueError, "draft name"):
            save_plan_draft("../escape", self.toml, self.root)
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            resolve_plan_draft(self.toml + '\ncommand = "make anything"\n', self.root)
        self.assertFalse((self.root / "plans/drafts").exists())


if __name__ == "__main__":
    unittest.main()
