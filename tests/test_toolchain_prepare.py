from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from fidb_poc.toolchain_prepare import (
    PREPARATION_SCHEMA,
    PreparationError,
    inspect_prepared,
    prepare_pinned_archive,
)


def _archive(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> str:
    with tarfile.open(path, "w:xz") as output:
        for member, payload in members:
            output.addfile(member, io.BytesIO(payload) if payload is not None else None)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file(
    name: str, payload: bytes, *, mode: int = 0o644
) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = mode
    return member, payload


class ToolchainPreparationTests(unittest.TestCase):
    def test_prepares_zip_with_executable_and_relative_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "pack.zip"
            with zipfile.ZipFile(archive, "w") as output:
                directory = zipfile.ZipInfo("toolchain/bin/")
                directory.external_attr = (0o40755 << 16) | 0x10
                output.writestr(directory, b"")
                executable = zipfile.ZipInfo("toolchain/bin/cc")
                executable.external_attr = 0o100755 << 16
                output.writestr(executable, b"compiler")
                symlink = zipfile.ZipInfo("toolchain/bin/current-cc")
                symlink.external_attr = 0o120777 << 16
                output.writestr(symlink, b"cc")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()

            result = prepare_pinned_archive(
                archive,
                digest,
                archive.stat().st_size,
                "toolchain",
                root / "prepared",
                max_extracted_bytes=1024,
            )

            self.assertTrue((result.root / "bin/cc").stat().st_mode & 0o111)
            self.assertTrue((result.root / "bin/current-cc").is_symlink())
            self.assertEqual((result.root / "bin/current-cc").readlink(), Path("cc"))
            self.assertEqual(result.symlinks, 1)

    def test_zip_traversal_special_members_and_expansion_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.zip"
            with zipfile.ZipFile(traversal, "w") as output:
                output.writestr("../../escape", b"bad")
            traversal_digest = hashlib.sha256(traversal.read_bytes()).hexdigest()
            with self.assertRaisesRegex(PreparationError, "escapes extraction root"):
                prepare_pinned_archive(
                    traversal,
                    traversal_digest,
                    traversal.stat().st_size,
                    "toolchain",
                    root / "prepared-traversal",
                    max_extracted_bytes=1024,
                )
            self.assertFalse((root / "escape").exists())

            special = root / "special.zip"
            with zipfile.ZipFile(special, "w") as output:
                fifo = zipfile.ZipInfo("toolchain/fifo")
                fifo.external_attr = 0o010644 << 16
                output.writestr(fifo, b"")
            special_digest = hashlib.sha256(special.read_bytes()).hexdigest()
            with self.assertRaisesRegex(PreparationError, "special member"):
                prepare_pinned_archive(
                    special,
                    special_digest,
                    special.stat().st_size,
                    "toolchain",
                    root / "prepared-special-zip",
                    max_extracted_bytes=1024,
                )

            oversized = root / "oversized.zip"
            with zipfile.ZipFile(oversized, "w") as output:
                output.writestr("toolchain/large", b"x" * 128)
            oversized_digest = hashlib.sha256(oversized.read_bytes()).hexdigest()
            with self.assertRaisesRegex(PreparationError, "expands to"):
                prepare_pinned_archive(
                    oversized,
                    oversized_digest,
                    oversized.stat().st_size,
                    "toolchain",
                    root / "prepared-oversized-zip",
                    max_extracted_bytes=64,
                )

    def test_zip_rejects_material_nested_beneath_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "nested.zip"
            with zipfile.ZipFile(archive, "w") as output:
                symlink = zipfile.ZipInfo("toolchain/link")
                symlink.external_attr = 0o120777 << 16
                output.writestr(symlink, b"real")
                output.writestr("toolchain/link/escape", b"bad")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()

            with self.assertRaisesRegex(PreparationError, "non-directory"):
                prepare_pinned_archive(
                    archive,
                    digest,
                    archive.stat().st_size,
                    "toolchain",
                    root / "prepared",
                    max_extracted_bytes=1024,
                )

    def test_prepares_atomically_and_reuses_sealed_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "pack.tar.xz"
            directory = tarfile.TarInfo("toolchain")
            directory.type = tarfile.DIRTYPE
            link = tarfile.TarInfo("toolchain/lib/current")
            link.type = tarfile.SYMTYPE
            link.linkname = "../real/libc.so"
            digest = _archive(
                archive,
                [
                    (directory, None),
                    _file("toolchain/bin/cc", b"compiler", mode=0o755),
                    _file("toolchain/real/libc.so", b"runtime"),
                    (link, None),
                ],
            )
            prepared = root / "prepared"

            first = prepare_pinned_archive(
                archive,
                digest,
                archive.stat().st_size,
                "toolchain",
                prepared,
                max_extracted_bytes=1024,
            )
            second = prepare_pinned_archive(
                archive,
                digest,
                archive.stat().st_size,
                "toolchain",
                prepared,
                max_extracted_bytes=1024,
            )

            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(first.root, prepared / digest / "toolchain")
            self.assertTrue((first.root / "bin/cc").is_file())
            self.assertTrue((first.root / "bin/cc").stat().st_mode & 0o111)
            self.assertTrue((first.root / "lib/current").is_symlink())
            inspection = inspect_prepared(prepared, digest, "toolchain")
            self.assertEqual(inspection.state, "prepared")
            self.assertEqual(inspection.manifest["schema_version"], PREPARATION_SCHEMA)
            self.assertFalse(any(prepared.glob(f".{digest}.*")))

    def test_traversal_archive_never_publishes_or_escapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "malicious.tar.xz"
            digest = _archive(archive, [_file("../../escape", b"bad")])
            prepared = root / "prepared"

            with self.assertRaisesRegex(PreparationError, "escapes extraction root"):
                prepare_pinned_archive(
                    archive,
                    digest,
                    archive.stat().st_size,
                    "toolchain",
                    prepared,
                    max_extracted_bytes=1024,
                )

            self.assertFalse((root / "escape").exists())
            self.assertFalse((prepared / digest).exists())

    def test_special_members_and_expansion_limit_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            special = root / "special.tar.xz"
            fifo = tarfile.TarInfo("toolchain/fifo")
            fifo.type = tarfile.FIFOTYPE
            special_digest = _archive(special, [(fifo, None)])
            with self.assertRaisesRegex(PreparationError, "special member"):
                prepare_pinned_archive(
                    special,
                    special_digest,
                    special.stat().st_size,
                    "toolchain",
                    root / "prepared-special",
                    max_extracted_bytes=1024,
                )

            oversized = root / "oversized.tar.xz"
            oversized_digest = _archive(
                oversized, [_file("toolchain/large", b"x" * 128)]
            )
            with self.assertRaisesRegex(PreparationError, "expands to"):
                prepare_pinned_archive(
                    oversized,
                    oversized_digest,
                    oversized.stat().st_size,
                    "toolchain",
                    root / "prepared-oversized",
                    max_extracted_bytes=64,
                )

    def test_broken_existing_preparation_is_quarantined(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "pack.tar.xz"
            digest = _archive(archive, [_file("toolchain/bin/cc", b"compiler")])
            prepared = root / "prepared"
            broken = prepared / digest
            broken.mkdir(parents=True)
            (broken / ".fidb-prepared.json").write_text(
                json.dumps({"schema_version": "wrong"}), encoding="utf-8"
            )

            result = prepare_pinned_archive(
                archive,
                digest,
                archive.stat().st_size,
                "toolchain",
                prepared,
                max_extracted_bytes=1024,
            )

            self.assertIsNotNone(result.quarantined)
            assert result.quarantined is not None
            self.assertTrue(result.quarantined.is_dir())
            self.assertEqual(
                inspect_prepared(prepared, digest, "toolchain").state, "prepared"
            )


if __name__ == "__main__":
    unittest.main()
