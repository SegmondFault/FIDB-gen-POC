import unittest
from contextlib import nullcontext
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

from fidb_poc.ghidra_fid import (
    LSDA_LOGGER_NAME,
    _BoundedLsdaErrorLogger,
    analyze_and_export_program_signatures,
    _configure_fid_build_analysis,
    _configure_target_analysis,
    _deduplicated_relation_rows,
    _safe_project_name,
    _safe_project_location,
    _set_registered_analysis_boolean_option,
)
from fidb_poc.validation_analysis import (
    FID_BUILD_ANALYSIS_POLICY,
    FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY,
    FID_BUILD_RECOVERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_POLICY,
    QUERY_ANALYSIS_RECOVERY_POLICY,
)


class _Options:
    def __init__(self, names=()):
        self.names = set(names)
        self.children = {}
        self.values = {}

    def contains(self, name):
        return name in self.names

    def getOptions(self, name):
        return self.children[name]

    def setBoolean(self, name, value):
        self.values[name] = value


class _LogSource:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class _LogDelegate:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*arguments):
            self.calls.append((name, arguments))

        return record


class GhidraTargetAnalysisPolicyTests(unittest.TestCase):
    def test_lsda_limiter_bounds_only_the_pathological_error_source(self):
        now = [100.0]
        delegate = _LogDelegate()
        logger = _BoundedLsdaErrorLogger(delegate, clock=lambda: now[0])
        lsda = _LogSource(LSDA_LOGGER_NAME)
        unrelated = _LogSource("other.Analyzer")

        for index in range(100):
            logger.error(lsda, f"repeated {index}")
        logger.warn(lsda, "not an error")
        logger.error(unrelated, "unrelated error")
        now[0] += 3.0
        logger.error(lsda, "one replenished token")

        self.assertEqual(logger.passed_lsda, 21)
        self.assertEqual(logger.suppressed_lsda, 80)
        self.assertEqual(len(delegate.calls), 23)
        self.assertEqual(delegate.calls[-1][1][1], "one replenished token")

    def test_project_names_sanitize_recipe_punctuation_without_collisions(self):
        plus = _safe_project_name("FIDB_boringssl_14.0.0+r45_3_linux_x86")
        dash = _safe_project_name("FIDB_boringssl_14.0.0-r45_3_linux_x86")

        self.assertNotIn("+", plus)
        self.assertNotIn("-", dash)
        self.assertNotEqual(plus, dash)
        self.assertEqual(
            _safe_project_name("FIDB_openssl_3.5.8_linux_x86"),
            "FIDB_openssl_3.5.8_linux_x86",
        )

    def test_project_locations_sanitize_only_the_recipe_leaf(self):
        parent = Path("/tmp/attempt-with-dash/projects")
        plus = _safe_project_location(parent / "boringssl-14.0.0+r45-3")
        dash = _safe_project_location(parent / "boringssl-14.0.0-r45-3")

        self.assertEqual(plus.parent, parent)
        self.assertNotIn("+", plus.name)
        self.assertNotEqual(plus, dash)

    def test_fid_build_recovery_layers_on_fid_safe_analysis(self):
        program = object()
        with (
            patch("fidb_poc.ghidra_fid._configure_fid_safe_analysis") as safe,
            patch(
                "fidb_poc.ghidra_fid._set_registered_analysis_analyzer_enablement"
            ) as enablement,
        ):
            _configure_fid_build_analysis(program, FID_BUILD_RECOVERY_ANALYSIS_POLICY)

        safe.assert_called_once_with(program)
        enablement.assert_called_once_with(
            program,
            {
                "Call-Fixup Installer": False,
                "Non-Returning Functions - Discovered": False,
            },
        )

    def test_fid_build_default_is_only_fid_safe_analysis(self):
        program = object()
        with (
            patch("fidb_poc.ghidra_fid._configure_fid_safe_analysis") as safe,
            patch(
                "fidb_poc.ghidra_fid._set_registered_analysis_analyzer_enablement"
            ) as enablement,
        ):
            _configure_fid_build_analysis(program, FID_BUILD_ANALYSIS_POLICY)

        safe.assert_called_once_with(program)
        enablement.assert_not_called()

    def test_relocatable_policy_disables_only_gcc_exception_analysis(self):
        program = object()
        with (
            patch("fidb_poc.ghidra_fid._configure_fid_safe_analysis") as safe,
            patch(
                "fidb_poc.ghidra_fid._set_registered_analysis_analyzer_enablement"
            ) as enablement,
        ):
            _configure_fid_build_analysis(
                program, FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY
            )

        safe.assert_called_once_with(program)
        enablement.assert_called_once_with(program, {"GCC Exception Handlers": False})

    def test_missing_project_journal_rebuilds_once_then_exports(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "project"
            parent.mkdir()
            (parent / "stale").write_text("old", encoding="utf-8")
            summary = {"evidence_schema": "fidb-program-signature-evidence/v1"}
            with (
                patch(
                    "fidb_poc.ghidra_fid.analyze_target",
                    return_value=(parent, "/query.elf"),
                ) as analyze,
                patch(
                    "fidb_poc.ghidra_fid.export_program_signatures",
                    side_effect=[
                        RuntimeError(
                            "java.io.FileNotFoundException: compact-query.rep/"
                            "idata/~journal.dat"
                        ),
                        summary,
                    ],
                ) as export,
            ):
                result = analyze_and_export_program_signatures(
                    Path(temporary) / "query.elf",
                    parent,
                    "compact-query",
                    "x86:LE:64:default",
                    Path(temporary) / "query-signatures.jsonl",
                    "gcc",
                )

        self.assertEqual(result[2], summary)
        self.assertEqual(result[3], 1)
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(export.call_count, 2)

    def test_unrecognised_export_error_is_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "project"
            with (
                patch(
                    "fidb_poc.ghidra_fid.analyze_target",
                    return_value=(parent, "/query.elf"),
                ) as analyze,
                patch(
                    "fidb_poc.ghidra_fid.export_program_signatures",
                    side_effect=RuntimeError("different failure"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "different failure"):
                    analyze_and_export_program_signatures(
                        Path(temporary) / "query.elf",
                        parent,
                        "compact-query",
                        "x86:LE:64:default",
                        Path(temporary) / "query-signatures.jsonl",
                        "gcc",
                    )

        analyze.assert_called_once()

    def test_relation_evidence_is_sorted_and_deduplicated_by_full_hash(self):
        first = Mock()
        first.getEntryPoint.return_value = "1000"
        duplicate = Mock()
        duplicate.getEntryPoint.return_value = "2000"
        second = Mock()
        second.getEntryPoint.return_value = "3000"
        first_hash = Mock()
        first_hash.getFullHash.return_value = 0x20
        first_hash.getCodeUnitSize.return_value = 4
        duplicate_hash = Mock()
        duplicate_hash.getFullHash.return_value = 0x20
        duplicate_hash.getCodeUnitSize.return_value = 4
        second_hash = Mock()
        second_hash.getFullHash.return_value = 0x10
        second_hash.getCodeUnitSize.return_value = 7
        service = Mock()
        service.hashFunction.side_effect = [first_hash, duplicate_hash, second_hash]

        rows = _deduplicated_relation_rows([first, duplicate, second], service, {})

        self.assertEqual(
            rows,
            [
                {"full_hash": "0000000000000010", "code_unit_size": 7},
                {"full_hash": "0000000000000020", "code_unit_size": 4},
            ],
        )

    def test_default_policy_is_a_noop(self):
        _configure_target_analysis(object(), QUERY_ANALYSIS_POLICY)

    def test_superh_recovery_disables_both_repair_producers(self):
        analyzers = (
            "Call-Fixup Installer",
            "Non-Returning Functions - Discovered",
        )
        options = _Options(analyzers)
        program = object()

        with (
            patch(
                "fidb_poc.ghidra_fid.pyghidra.analysis_properties",
                return_value=options,
            ) as analysis_properties,
            patch(
                "fidb_poc.ghidra_fid.pyghidra.transaction",
                return_value=nullcontext(),
            ) as transaction,
        ):
            _configure_target_analysis(program, QUERY_ANALYSIS_RECOVERY_POLICY)

        analysis_properties.assert_called_once_with(program)
        transaction.assert_called_once_with(
            program, "Configure FIDB target analyzer policy"
        )
        self.assertEqual(options.values, {name: False for name in analyzers})

    def test_unknown_policy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported query analysis policy"):
            _configure_target_analysis(object(), "unknown")

    def test_recovery_fails_closed_when_analyzer_is_not_registered(self):
        with patch(
            "fidb_poc.ghidra_fid.pyghidra.analysis_properties",
            return_value=_Options(),
        ):
            with self.assertRaisesRegex(RuntimeError, "analyzers are unavailable"):
                _configure_target_analysis(object(), QUERY_ANALYSIS_RECOVERY_POLICY)

    def test_child_option_helper_fails_closed_when_option_is_not_registered(self):
        analyzer = "Non-Returning Functions - Discovered"
        options = _Options([analyzer])
        options.children[analyzer] = _Options()
        with patch(
            "fidb_poc.ghidra_fid.pyghidra.analysis_properties",
            return_value=options,
        ):
            with self.assertRaisesRegex(RuntimeError, "analyzer option is unavailable"):
                _set_registered_analysis_boolean_option(
                    object(),
                    analyzer_name=analyzer,
                    option_name="Repair Flow Damage",
                    value=False,
                )


if __name__ == "__main__":
    unittest.main()
