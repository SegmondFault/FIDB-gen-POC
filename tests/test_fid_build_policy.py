import tempfile
import unittest
from pathlib import Path

from fidb_poc.config import load_configuration, select_configuration
from fidb_poc.fid_build_policy import load_fid_build_policy
from fidb_poc.validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
    GHIDRA_DEFAULT_DIAGNOSTIC_POLICY,
    GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY,
)


class FidBuildPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            cls.project_root / "worker.toml", request_override=("protobuf@36.1",)
        )
        cls.configuration = select_configuration(
            configuration,
            route_ids=("linux-mips32-be-gcc",),
            treatment_ids=("optimization_o0",),
            profile=None,
        )

    def _write_authority(self, root: Path, *, enabled: bool = True) -> Path:
        path = root / "performance/fid-build-analysis.toml"
        path.parent.mkdir(parents=True)
        path.write_text(
            'schema_version = "fidb-fid-build-policy/v1"\n'
            'default_analysis_policy = "ghidra-fid-safe-analysis-v1"\n'
            'default_diagnostic_policy = "ghidra-default-diagnostics-v1"\n\n'
            "[[rule]]\n"
            'id = "protobuf-mips-relocatable-exception-analysis-v1"\n'
            f"enabled = {str(enabled).lower()}\n"
            'libraries = ["protobuf"]\n'
            'route_prefixes = ["linux-mips32-be-", "linux-mips32-le-"]\n'
            'artifact_shapes = ["static-archive-members"]\n'
            "analysis_policy = "
            '"ghidra-fid-safe-relocatable-gcc-exception-disabled-v1"\n'
            'diagnostic_policy = "ghidra-lsda-burst-20-per-minute-v1"\n',
            encoding="utf-8",
        )
        return path

    def test_enabled_rule_selects_bounded_mips_relocatable_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_authority(root)
            authority = load_fid_build_policy(root)
            selection = authority.select(
                self.configuration.libraries[0],
                self.configuration.routes[0],
                self.configuration.treatments[0],
            )

        self.assertEqual(
            selection.analysis_policy,
            FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
        )
        self.assertEqual(
            selection.diagnostic_policy, GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY
        )
        self.assertEqual(
            selection.rule_id, "protobuf-mips-relocatable-exception-analysis-v1"
        )
        self.assertEqual(len(selection.authority_sha256), 64)

    def test_disabled_rule_preserves_canonical_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write_authority(root, enabled=False)
            authority = load_fid_build_policy(root)
            selection = authority.select(
                self.configuration.libraries[0],
                self.configuration.routes[0],
                self.configuration.treatments[0],
            )

        self.assertEqual(selection.rule_id, "default")
        self.assertEqual(selection.analysis_policy, FID_BUILD_ANALYSIS_POLICY)
        self.assertEqual(selection.diagnostic_policy, GHIDRA_DEFAULT_DIAGNOSTIC_POLICY)

    def test_authority_rejects_unknown_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._write_authority(root)
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "ghidra-lsda-burst-20-per-minute-v1", "unreviewed"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported"):
                load_fid_build_policy(root)

    def test_checked_in_authority_bounds_mips_logs_without_changing_analysis(self):
        authority = load_fid_build_policy(self.project_root)
        selection = authority.select(
            self.configuration.libraries[0],
            self.configuration.routes[0],
            self.configuration.treatments[0],
        )

        self.assertEqual(selection.rule_id, "protobuf-mips-lsda-diagnostic-bound-v1")
        self.assertEqual(selection.analysis_policy, FID_BUILD_ANALYSIS_POLICY)
        self.assertEqual(
            selection.diagnostic_policy, GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY
        )


if __name__ == "__main__":
    unittest.main()
