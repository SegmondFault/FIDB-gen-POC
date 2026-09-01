from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from fidb_poc.toolchain_inputs import (
    INPUT_BINDING_SCHEMA,
    InputBindingError,
    bind_input,
    inspect_input_binding,
)

AUTHORITY = {
    "id": "apple-macos-sdk",
    "kind": "user-supplied-sdk",
    "target_ids": ["macos-arm64-macho"],
    "authority": "https://authority.invalid/sdk",
    "required_metadata": [
        "xcode_version",
        "sdk_version",
        "deployment_target",
        "sha256",
        "bytes",
    ],
}


def _metadata(digest: str, byte_count: int) -> dict[str, str]:
    return {
        "xcode_version": "26.0",
        "sdk_version": "26.0",
        "deployment_target": "13.0",
        "sha256": digest,
        "bytes": str(byte_count),
    }


class ToolchainInputBindingTests(unittest.TestCase):
    def test_binding_copies_privately_verifies_and_reuses_material(self):
        payload = b"licensed SDK package"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "MacOSX.sdk.tar.xz"
            source.write_bytes(payload)

            first = bind_input(
                root,
                AUTHORITY,
                source,
                digest,
                len(payload),
                _metadata(digest, len(payload)),
            )
            second = bind_input(
                root,
                AUTHORITY,
                source,
                digest,
                len(payload),
                _metadata(digest, len(payload)),
            )

            self.assertFalse(first.material_cache_hit)
            self.assertTrue(second.material_cache_hit)
            self.assertEqual(first.material_path.read_bytes(), payload)
            self.assertEqual(first.material_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(first.binding_path.stat().st_mode & 0o777, 0o600)
            inspection = inspect_input_binding(root, AUTHORITY)
            self.assertEqual(inspection.state, "bound-verified")
            self.assertEqual(
                inspection.document["schema_version"], INPUT_BINDING_SCHEMA
            )

    def test_digest_size_and_metadata_mismatches_fail_without_binding(self):
        payload = b"licensed SDK package"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "MacOSX.sdk.tar.xz"
            source.write_bytes(payload)
            with self.assertRaisesRegex(InputBindingError, "byte count mismatch"):
                bind_input(
                    root,
                    AUTHORITY,
                    source,
                    digest,
                    len(payload) + 1,
                    _metadata(digest, len(payload)),
                )
            with self.assertRaisesRegex(InputBindingError, "metadata must contain"):
                bind_input(
                    root,
                    AUTHORITY,
                    source,
                    digest,
                    len(payload),
                    {"sdk_version": "26.0"},
                )
            with self.assertRaisesRegex(InputBindingError, "digest"):
                bind_input(
                    root,
                    AUTHORITY,
                    source,
                    "0" * 64,
                    len(payload),
                    _metadata("0" * 64, len(payload)),
                )

            self.assertEqual(inspect_input_binding(root, AUTHORITY).state, "missing")

    def test_tampered_material_or_binding_is_broken(self):
        payload = b"licensed SDK package"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "MacOSX.sdk.tar.xz"
            source.write_bytes(payload)
            result = bind_input(
                root,
                AUTHORITY,
                source,
                digest,
                len(payload),
                _metadata(digest, len(payload)),
            )
            result.material_path.write_bytes(b"tampered SDK package")
            self.assertEqual(inspect_input_binding(root, AUTHORITY).state, "broken")

            result.binding_path.write_text(
                json.dumps({"schema_version": "wrong"}), encoding="utf-8"
            )
            self.assertEqual(inspect_input_binding(root, AUTHORITY).state, "broken")


if __name__ == "__main__":
    unittest.main()
