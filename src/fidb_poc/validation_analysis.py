"""Semantic identities for machine-validation query analysis."""

QUERY_ANALYSIS_POLICY = "ghidra-default-auto-analysis-v1"
QUERY_ANALYSIS_RECOVERY_POLICY_V1 = (
    "superh-no-return-flow-repair-disabled-after-timeout-v1"
)
QUERY_ANALYSIS_RECOVERY_POLICY = (
    "superh-clear-flow-repair-analyzers-disabled-after-timeout-v1"
)

FID_BUILD_ANALYSIS_POLICY = "ghidra-fid-safe-analysis-v1"
FID_BUILD_RECOVERY_ANALYSIS_POLICY = (
    "ghidra-fid-safe-superh-clear-flow-repair-analyzers-disabled-after-timeout-v1"
)
FID_BUILD_RELOCATABLE_GCC_EXCEPTION_DISABLED_POLICY = (
    "ghidra-fid-safe-relocatable-gcc-exception-disabled-v1"
)

GHIDRA_DEFAULT_DIAGNOSTIC_POLICY = "ghidra-default-diagnostics-v1"
GHIDRA_LSDA_BURST_DIAGNOSTIC_POLICY = "ghidra-lsda-burst-20-per-minute-v1"
