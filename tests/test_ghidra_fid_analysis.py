import sys
import types
import unittest
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
        program = types.SimpleNamespace(getOptions=lambda _name: options)

        listing = types.ModuleType("ghidra.program.model.listing")
        listing.Program = types.SimpleNamespace(ANALYSIS_PROPERTIES="Analysis")
        modules = {
            "ghidra": types.ModuleType("ghidra"),
            "ghidra.program": types.ModuleType("ghidra.program"),
            "ghidra.program.model": types.ModuleType("ghidra.program.model"),
            "ghidra.program.model.listing": listing,
        }
        with patch.dict(sys.modules, modules):
            _configure_target_analysis(program, QUERY_ANALYSIS_RECOVERY_POLICY)

        self.assertEqual(nested.values, {repair: False})

    def test_unknown_policy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported query analysis policy"):
            _configure_target_analysis(object(), "unknown")


if __name__ == "__main__":
    unittest.main()
