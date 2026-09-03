# Staged backend experiment

This crate is an optional scheduler experiment. It does not replace the
normal Python/PyGhidra executor and is not selected by any queue or performance
profile.

The experiment splits a width cell at a digest-sealed JSON boundary:

1. compiler-only workers prepare validated object sets without starting Java;
2. a bounded queue feeds those sets to long-lived PyGhidra service processes;
3. each service process reuses its one embedded JVM for subsequent cells; and
4. the benchmark harness compares canonical FID signature records against a
   result made by the normal backend.

Rust supervises subprocesses and the bounded queue with Tokio. Ghidra analysis
itself remains the existing Python/JPype/Java implementation, so this design
does not attempt to reimplement Ghidra or remove the JVM compatibility
boundary. The service protocol prefixes machine results with `FIDB_RESULT` so
native Ghidra console output cannot be mistaken for JSON.

## Build and inspect

Install a stable Rust toolchain, then run:

```sh
cargo build --locked --release \
  --manifest-path experiments/rust-staged/Cargo.toml
cargo test --locked \
  --manifest-path experiments/rust-staged/Cargo.toml
```

The tracked `Cargo.lock` fixes the dependency graph. Build output is ignored
under `experiments/rust-staged/target/`.

Previewing a benchmark is disarmed:

```sh
fidb-poc benchmark-backend --project-root . \
  --backend rust-staged-v1 \
  --route linux-x86-64-gcc-13 \
  --treatment baseline_o2 \
  --build-workers 4 --analysis-workers 2
```

Execution additionally requires `--execute`, `--rust-binary`, and the same
Ghidra environment as the normal worker. Results are isolated below the
ignored `artifacts/benchmarks/backend-experiments/` directory and do not count
as width evidence.

## Correctness and rollback

An alternate backend is acceptable only when the resolved-width authority and
canonical FID records match the reference backend. Object-byte differences
and raw FIDB container/order differences are retained separately rather than
silently declared semantic failures.

Rollback is simply to keep using the normal executor; no queue or production
configuration refers to this crate. The entire experiment can be removed by
deleting this directory and the `benchmark-backend` command without migrating
stored width evidence.

WGPU is intentionally absent. The measured signature-ledger transformation is
a very small share of end-to-end time, while the dominant operation remains
Ghidra analysis in Java. A GPU implementation should be reconsidered only if
profiling a later database/deduplication stage identifies a substantial,
parallel numeric kernel.

## Qualification decision

On the fixed ten-route OpenSSL workload, this supervisor completed in 839.857
seconds and process-staged Python in 839.860 seconds. The 3.2 ms difference is
not operationally meaningful. Both matched all canonical FID records and were
only 0.395% faster than the normal executor's 843.187 seconds. Rust therefore
remains an optional specimen and is not a project runtime dependency. Full
measurements and raw evidence hashes are tracked in
[`benchmarks/staged-backends-reference-host-2026-09-03.toml`](../../benchmarks/staged-backends-reference-host-2026-09-03.toml).
