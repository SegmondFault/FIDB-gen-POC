from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from fidb_poc.emulator_providers import emulator_status, load_emulator_registry


class EmulatorProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checkout = Path(__file__).resolve().parents[1]

    def project(self, temporary: str) -> Path:
        root = Path(temporary)
        (root / "emulators").mkdir()
        shutil.copy2(
            self.checkout / "emulators/registry.toml",
            root / "emulators/registry.toml",
        )
        return root

    def test_registry_declares_host_scoped_provider_and_target_map(self) -> None:
        registry = load_emulator_registry(self.checkout)
        provider = registry["managed_providers"][0]
        self.assertEqual(provider["host_os"], "linux")
        self.assertEqual(provider["host_architecture"], "x86_64")
        self.assertEqual(
            registry["qemu_user_targets"]["linux-mips32-le"],
            "qemu-mipsel-static",
        )

    def test_unsupported_host_still_has_platform_neutral_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.project(temporary)
            with mock.patch(
                "fidb_poc.emulator_providers._host_identity",
                return_value=("macos", "aarch64"),
            ):
                status = emulator_status(root)
        self.assertEqual(status["state"], "unavailable")
        self.assertEqual(status["host"], {"os": "macos", "architecture": "aarch64"})
        self.assertIn("compatible worker", status["message"])

    def test_external_installation_is_explicit_and_probeable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.project(temporary)
            bin_root = root / "external-qemu"
            bin_root.mkdir()
            executable = bin_root / "qemu-mipsel"
            executable.write_text("#!/bin/sh\necho 'qemu test 1.0'\n", encoding="utf-8")
            executable.chmod(0o755)
            (root / "emulators/local.toml").write_text(
                "\n".join(
                    (
                        'schema_version = "fidb-emulator-local/v1"',
                        'provider = "external"',
                        'engine = "qemu"',
                        'mode = "user"',
                        f'root = "{bin_root}"',
                        "",
                        "[executables]",
                        'linux-mips32-le = "qemu-mipsel"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            status = emulator_status(root, probe=True)
        self.assertEqual(status["provider_kind"], "external")
        self.assertEqual(status["state"], "ready")
        self.assertEqual(
            status["targets"]["linux-mips32-le"]["version"], "qemu test 1.0"
        )
        self.assertEqual(
            status["targets"]["linux-mips32-le"]["sha256"],
            hashlib.sha256(b"#!/bin/sh\necho 'qemu test 1.0'\n").hexdigest(),
        )

    def test_external_status_does_not_execute_without_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.project(temporary)
            bin_root = root / "external-qemu"
            bin_root.mkdir()
            executable = bin_root / "qemu-arm"
            executable.write_text("not executed", encoding="utf-8")
            executable.chmod(0o755)
            (root / "emulators/local.toml").write_text(
                "\n".join(
                    (
                        'schema_version = "fidb-emulator-local/v1"',
                        'provider = "external"',
                        'engine = "qemu"',
                        'mode = "user"',
                        f'root = "{bin_root}"',
                        "",
                        "[executables]",
                        'linux-arm32 = "qemu-arm"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            with mock.patch("fidb_poc.emulator_providers.subprocess.run") as run:
                status = emulator_status(root)
        run.assert_not_called()
        self.assertEqual(status["state"], "ready")

    def test_managed_provider_is_missing_before_pull(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.project(temporary)
            with mock.patch(
                "fidb_poc.emulator_providers._host_identity",
                return_value=("linux", "x86_64"),
            ):
                status = emulator_status(root)
        self.assertEqual(status["provider_kind"], "managed")
        self.assertEqual(status["state"], "missing")
        self.assertEqual(status["cache"]["state"], "missing")


if __name__ == "__main__":
    unittest.main()
