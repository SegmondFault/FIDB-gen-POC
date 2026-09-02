from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from fidb_poc.external_workers import (
    EXTERNAL_PREFLIGHT_SCHEMA,
    load_external_toolchain,
    preflight_external_toolchain,
    validate_registration,
)


class ExternalWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]

    def test_repository_definition_is_cross_checked_and_language_declared(self):
        definition = load_external_toolchain("macos-arm64-apple-clang", self.root)
        self.assertEqual(definition.worker_pool, "macos-native")
        self.assertEqual(definition.probe_kind, "apple-xcode")
        self.assertEqual(definition.languages, ("c", "cpp"))
        self.assertEqual(len(definition.sha256), 64)

    def test_apple_preflight_fails_closed_without_probing_xcode_on_linux(self):
        definition = load_external_toolchain("macos-arm64-apple-clang", self.root)
        document = preflight_external_toolchain(definition, self.root)
        self.assertEqual(document["schema_version"], EXTERNAL_PREFLIGHT_SCHEMA)
        self.assertFalse(document["ready"])
        self.assertIn("host-system-mismatch:linux", document["blockers"])
        self.assertNotIn("required_tools", document["toolchain"])

    def test_registration_rejects_changed_definition_identity(self):
        definition = load_external_toolchain("macos-arm64-apple-clang", self.root)
        metadata = {name: "present" for name in definition.required_metadata}
        document = {
            "schema_version": EXTERNAL_PREFLIGHT_SCHEMA,
            "checked_at": "2026-09-02T08:00:00+00:00",
            "ready": True,
            "definition": definition.registration_identity(),
            "host": {},
            "toolchain": {},
            "analysis": {},
            "smoke": {},
            "resources": {},
            "metadata": metadata,
            "blockers": [],
        }
        self.assertEqual(validate_registration(document, definition), document)
        changed = json.loads(json.dumps(document))
        changed["definition"]["languages"] = ["swift"]
        with self.assertRaisesRegex(ValueError, "identity changed"):
            validate_registration(changed, definition)

    def test_definition_reference_cannot_escape_external_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "outside.toml"
            outside.write_text("schema_version = 'invented'", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escaped"):
                load_external_toolchain(outside, self.root)


if __name__ == "__main__":
    unittest.main()
