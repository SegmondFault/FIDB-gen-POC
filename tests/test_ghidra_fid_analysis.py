import unittest
from contextlib import nullcontext
from unittest.mock import patch

from fidb_poc.ghidra_fid import _configure_target_analysis
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
    def test_default_policy_is_a_noop(self):
        _configure_target_analysis(object(), QUERY_ANALYSIS_POLICY)

    def test_superh_recovery_disables_only_nonreturn_flow_repair(self):
        analyzer = "Non-Returning Functions - Discovered"
        repair = "Repair Flow Damage"
        nested = _Options([repair])
        options = _Options([analyzer])
        options.children[analyzer] = nested
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
            program, "Configure FIDB target analysis policy"
        )
        self.assertEqual(nested.values, {repair: False})

    def test_unknown_policy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported query analysis policy"):
            _configure_target_analysis(object(), "unknown")

    def test_recovery_fails_closed_when_analyzer_is_not_registered(self):
        with patch(
            "fidb_poc.ghidra_fid.pyghidra.analysis_properties",
            return_value=_Options(),
        ):
            with self.assertRaisesRegex(RuntimeError, "analyzer is unavailable"):
                _configure_target_analysis(object(), QUERY_ANALYSIS_RECOVERY_POLICY)

    def test_recovery_fails_closed_when_child_option_is_not_registered(self):
        analyzer = "Non-Returning Functions - Discovered"
        options = _Options([analyzer])
        options.children[analyzer] = _Options()
        with patch(
            "fidb_poc.ghidra_fid.pyghidra.analysis_properties",
            return_value=options,
        ):
            with self.assertRaisesRegex(RuntimeError, "analyzer option is unavailable"):
                _configure_target_analysis(object(), QUERY_ANALYSIS_RECOVERY_POLICY)


if __name__ == "__main__":
    unittest.main()
