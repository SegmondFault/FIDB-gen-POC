# Performance evidence

This directory retains compact, reviewable conclusions from bounded pipeline
benchmarks. Raw benchmark work and result JSON remain ignored under
`artifacts/benchmarks/`; those runs are operational measurements, not width or
lane coverage evidence.

Each tracked record names and hashes its raw result, fixes the subject and
routes, records correctness comparisons, and states the decision the evidence
supports. A performance result may change execution policy only when the
produced analysis artifacts and signature ledgers match the compatibility
baseline. It never authorizes a queue or changes coverage membership.

Re-run a case with `fidb-poc benchmark-width`. Preview is disarmed; only the
explicit `--execute` form compiles or starts Ghidra.
