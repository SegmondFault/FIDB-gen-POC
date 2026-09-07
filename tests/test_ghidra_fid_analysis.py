import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch

from fidb_poc.ghidra_fid import (
    _configure_target_analysis,
    _deduplicated_relation_rows,
    _set_registered_analysis_boolean_option,
)
from fidb_poc.validation_analysis import (
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


class GhidraTargetAnalysisPolicyTests(unittest.TestCase):
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

        rows = _deduplicated_relation_rows(
            [first, duplicate, second], service, {}
        )

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
