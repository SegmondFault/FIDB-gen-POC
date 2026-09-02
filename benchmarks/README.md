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

## Runner experiments

PyGhidra is the compatibility/reference route, not an architectural lock-in.
The current implementation already starts Ghidra in-process and calls its Java
program-loader, analysis and FID APIs through JPype; it does not launch one
`analyzeHeadless` process per object. Consequently, replacing Python
orchestration with Rust would not remove the per-worker JVM or Ghidra analysis
heap. It may still improve supervision, scheduling and ledger ingestion.

Any alternate runner must remain optional until it reproduces the reference
route's object-set digest, deterministic signature-ledger digest, signature
counts and analysis-policy identity. Candidate measurements, in order, are:

1. capture noisy Ghidra console output into bounded per-cell logs;
2. compare a direct Java `GhidraScript` driver with the same one-cell reference;
3. measure fixed-workload worker counts, not raw CPU percentage;
4. prototype a Rust or native supervisor only around proven process and queue
   overhead, while keeping the Python CLI and PyGhidra executor available.

This is an experiment boundary, not permission to replace the working route.

The 2026-09-03 redirected-console control completed the same capped-heap
x86-64 cell in 718.36 seconds versus 718.66 seconds with the normal captured
console, with the same semantic digest. The 0.04% difference is noise, so
console capture is a usability option rather than a throughput optimization;
the executor remains unchanged.

A fixed ten-route comparison also rejected reducing native compilation from
four jobs per cell to three. The candidate's wall time was 0.82% lower, but
aggregate compilation was 0.61% slower and peak RSS was 2.40% higher. Outputs
were identical. This is noise rather than a scheduling win, so the four-job
reference behavior remains in place.
