# Performance profiles

`profiles.toml` is the reviewed source of truth for width-executor resource
policy. It is deliberately separate from `worker.toml`, which describes build
routes, and from queue `max_workers`, which limits coordinator leases. Selecting
a performance profile does not arm a queue or start a run.

Inspect all profiles or one profile without executing work:

```sh
fidb-poc performance --project-root .
fidb-poc performance reference-host-94g-balanced --project-root .
```

Apply one exact profile to a disarmed width preview:

```sh
fidb-poc run-width --project-root . \
  --performance-profile reference-host-94g-balanced
```

Add `--execute` only after reviewing the compiled width, host pressure and
scratch capacity. A named profile cannot be combined with manual performance
flags: this keeps its identity unambiguous in the run evidence. Experiments can
still use the existing individual flags without a named profile.

## What a profile controls

- `workers`: concurrent isolated width cells. Each cell worker is a long-lived
  process that starts one embedded Ghidra JVM and may execute several cells.
- `build_jobs_per_cell`: nested compiler or `make` jobs within one cell.
- `ghidra_heap_mib`: the Java `-Xmx` ceiling. It is not memory allocated up
  front, nor is it an estimate of resident memory.
- `ghidra_core_limit`: optional `cpu.core.limit` visible to one Ghidra JVM.
  Omission preserves the host-visible default.

The current executor reuses each worker JVM rather than launching a new JVM for
every object or cell. PyGhidra is an in-process JPype bridge; bypassing its
Python API would not remove the Ghidra JVM or its heap. A native supervisor in
Rust could eventually improve scheduling and ledger mechanics, but replacing
Ghidra's Java analysis/FID implementation would be a separate compatibility
project rather than a memory tweak.

## Included policies

| Profile | Cell workers | Build jobs/cell | JVM max heap | Evidence class |
| --- | ---: | ---: | ---: | --- |
| `auto` | automatic, capped at 20 | 4 | 4 GiB | current default |
| `laptop-4c-8g` | 1 | 2 | 2 GiB | portable starting point |
| `laptop-4c-16g` | 2 | 2 | 3 GiB | portable starting point |
| `laptop-8c-16g` | 3 | 2 | 3 GiB | portable starting point |
| `laptop-8c-32g` | 6 | 2 | 4 GiB | portable starting point |
| `reference-host-94g-balanced` | 20 | 4 | 4 GiB | measured on OpenSSL |
| `reference-host-112g-throughput` | 29 | 4 | 4 GiB | derived from measured OpenSSL run |
| `m1-max-64g-balanced` | 8 | 2 | 4 GiB | portable starting point |

The laptop and M1 Max profiles are safe initial hypotheses, not benchmark
claims. Qualify them with a representative canary and record peak process-tree
RSS, memory pressure, failures and hashes/hour before increasing workers. The
M1 Max profile reserves practical headroom by limiting concurrent cells to
eight on its ten CPU cores and recognises that its 64 GiB is unified CPU/GPU
memory. It does not change the
separate Apple toolchain/licensing and external-worker rules.

## `reference-host` interpretation

The host has 16 physical cores and 32 hardware threads. Ghidra analysis is not
a perfectly compute-bound loop: imports, filesystem work, garbage collection
and serial sections leave execution slots available, so simultaneous logical
threads can improve throughput. On the same 29 OpenSSL cells, 29 workers were
18.21% faster than 20 and produced 22.26% more cells/hour, while peak aggregate
RSS rose 22.65% from 50.52 GB to 61.96 GB. This supports a burst profile; it
does not prove that every library has the same heap envelope.

Giving Linux roughly 112 GiB and the integrated GPU 16 GiB is therefore useful
for this workload: the pipeline does not use the GPU, and the extra system RAM
provides safer headroom for 29 workers and larger libraries. It does not make a
single Ghidra analysis faster. At 20 workers the measured run averaged roughly
15 CPU cores of work; at 29 workers it averaged roughly 20.6, so scheduling and
serial/tail effects remain relevant after memory pressure is relieved.

The 94 GiB balanced profile remains the cross-library default. Promote the
112 GiB throughput profile only after representative large-library canaries
show that its failure rate and hashes/hour remain favourable.

## Qualification loop

1. Preview a fixed route/treatment set with `benchmark-width` and a named
   profile.
2. Execute only that bounded benchmark.
3. Compare semantic digests as well as wall time, hashes/hour, peak RSS and
   scratch.
4. Test lower heap ceilings (first 3072 MiB, then 2048 MiB) on the largest
   representative cell; reject a cap on OOM, instability or semantic drift.
5. Sweep worker counts around the likely knee. CPU percentage alone is not the
   objective; successful unique hashes per wall hour is.
6. Update the TOML qualification and bind a compact evidence file only after a
   repeatable result.

## Staged-backend experiment

Compile/analysis separation now has an isolated, disarmed qualification path;
it is not selected by a performance profile or queue. Compiler-only processes
stream digest-sealed object sets into a bounded pool of long-lived PyGhidra
processes. The normal executor remains the production route.

On ten fixed OpenSSL baseline cells, the normal executor completed in 843.187
seconds. Process-staged Python completed in 839.860 seconds and the Rust/Tokio
supervisor in 839.857 seconds. The 3.2 millisecond difference between the two
staged schedulers is zero for operational purposes, and both were only 0.395%
ahead of the normal executor. All 133,052 canonical FID records matched.
Consequently Rust is not promoted and no Rust toolchain is required to run the
project. The optional crate is retained only as a reversible experiment.

The Python thread-pool prototype took 864.123 seconds because concurrent source
extraction amplified Python/GIL contention; spawned build processes corrected
that. Peak proportional memory was 25.46 GB for process-staged Python and 20.72
GB for the Rust observation, but their summed per-cell PSS maxima were almost
equal. Treat the whole-run difference as scheduling/overlap evidence, not proof
that Rust makes a JVM smaller. The observed ten-worker envelope was roughly
2.1–2.5 GB PSS per simultaneous worker, below the 4 GB heap ceiling.

A concurrent multi-slot service inside one JVM remains deliberately outside
this experiment. Ghidra exposes process-wide managers and PyGhidra/JVM startup
state; sharing them between simultaneous projects requires an explicit
thread-safety and fault-isolation qualification. Sequential JVM reuse already
occurs in the worker pools.

The tracked measurements and raw-result hashes are in
[`benchmarks/staged-backends-reference-host-2026-09-03.toml`](../benchmarks/staged-backends-reference-host-2026-09-03.toml).
The optional runner and rollback boundary are documented in
[`experiments/rust-staged/README.md`](../experiments/rust-staged/README.md).

## Campaign time model

`batch-planning.toml` is the inspectable timing authority for the next C
top-ten campaign. It reads the exact two width-batch authorities, the selected
performance profile and the fixed-29-route 20-worker OpenSSL measurement. It
weights the six treatments by their measured OpenSSL service-time ratios and
uses a bounded square-root source-line heuristic until each new library has a
direct measurement.

`fidb-poc plan-time-blocks` is read-only. It currently produces five blocks
whose central estimates are all at or below five hours and reports a separate
±40% uncertainty range. The control panel **Batches** workspace shows the same
compiled authority, including all 480 Android executions. Any width or profile
change refreshes the draft; materialization must bind its digest so a live
queue cannot change shape silently.
