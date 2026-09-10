# Development notes

This tracked document records bounded engineering improvements that are useful
to future maintainers but are not yet execution authority. Operational changes
remain controlled by reviewed TOML, tests, qualification gates and the agent
runbook.

## Bounded cross-block tail filling

Status: proposed and not implemented.

### Problem

The coordinator currently preserves batch order by allowing one execution block
to drain completely before the next block can supply work. This creates
head-of-line blocking when a few slow cells form the tail of a block.

The recovered Protobuf block observed on 2026-09-10 made the cost visible:

- 25 of 36 cells were complete;
- 11 cells remained in Ghidra analysis;
- only 11 of the configured 32 worker slots could be used;
- 21 slots, or 65.6% of the pool, remained idle even though the next qualified
  block was queued.

The slow cells did not consume the whole machine. Exclusivity at the block
boundary prevented ready work from using the remaining capacity. Interrupted
Musl and Protobuf runs also showed that calendar admission-to-drain time is a
poor throughput measure unless paused periods and discarded attempts are
removed.

### Proposed execution model

Keep batches atomic for evidence, validation, retention and export, but allow a
bounded amount of execution overlap:

1. Admit and preflight blocks in strict campaign order.
2. Continue claiming from the current block normally.
3. When its claimable tail cannot fill the global worker pool, allow unused
   slots to claim from the immediately following fully resolved and qualified
   block.
4. Permit at most two active blocks initially: the draining block and one
   look-ahead block.
5. Keep every job attached to its original batch identity and provenance.
6. Drain, seal, validate, retain and export each batch independently.

This is work-conserving scheduling, not a change to compilation, Ghidra
analysis, FID generation or the resulting evidence.

### Required invariants

- No block may be skipped, claimed before qualification, or admitted from an
  inactive campaign.
- Resolution preflight and the authority-failure circuit breaker apply before
  look-ahead claims exactly as they do for ordinary claims.
- The configured worker limit and memory, temperature, load and disk gates are
  global across all active blocks.
- A failure or pause in one block must not corrupt, relabel or silently discard
  work belonging to another block.
- Validation and export eligibility remain per fully drained and sealed block;
  partial execution is never presented as complete evidence.
- Retention must not collect an active or partially completed block.
- Queue pause must stop new claims across every active block while allowing the
  configured in-flight completion policy to operate.
- Schedule semantics must remain explicit. Because tail filling starts the next
  block early, it should occur near a cutoff only when that block's conservative
  duration estimate fits the remaining window, unless an operator explicitly
  authorises overrun.
- The feature must be TOML-controlled and safely disabled to recover the
  current single-active-block behaviour.

Suggested initial controls:

```toml
[operations.scheduling.tail_fill]
enabled = false
max_active_blocks = 2
minimum_idle_slots = 4
require_estimated_fit_before_cutoff = true
```

The exact authority location and names should follow the existing queue schema
rather than being added as an unrelated configuration source.

### Control-panel visibility

The operations and matrix views should show:

- the primary draining block and any look-ahead block separately;
- running, queued and completed cells for each block;
- workers occupied per block and globally;
- why tail filling is active, disabled or inhibited;
- the estimated cutoff fit used to admit overlapping work.

The interface must not imply that an overlapping block is sealed merely because
some of its cells are running.

### Validation plan

1. Add deterministic scheduler tests with one deliberately slow tail and a
   ready successor block.
2. Assert strict admission order, global worker limits, pause behaviour,
   circuit-breaker behaviour and cutoff-fit handling.
3. Run the same small mixed-duration canary with tail filling disabled and
   enabled.
4. Confirm identical resolved identities, artifacts, FID populations, seals
   and provenance between both modes.
5. Interrupt and recover the overlapping canary to prove that leases and
   evidence remain isolated by batch.
6. Benchmark hashes or sealed cells per wall-clock hour, peak resident memory,
   retries, failures and post-drain retention behaviour.

The default path should change only if the representative benchmark is
wall-time neutral or faster and produces identical evidence. A useful initial
acceptance target is at least a 10% wall-time improvement on an uneven workload
without increased failures or breached resource gates. The observed tail had
only 34.4% worker occupancy, so the local opportunity was much larger; a
campaign-wide 10–30% improvement is a hypothesis to measure, not a guarantee.

## MIPS relocatable-object exception-analysis cost

Status: observed in the Protobuf 36.1 MIPS tail; proposed experiments are not
implemented and must not alter an in-flight attempt.

### Evidence

The affected cells import 86 relocatable C++ object files individually. A
sample MIPS32 big-endian GCC 12 `optimization_o0` attempt contained about
54 MiB of objects and had already produced an approximately 1.9 GiB Ghidra
project. Its Ghidra application logs occupied about 600 MiB and contained about
5.9 million repeated `LSDACallSiteTable` errors reporting call-site or landing-
pad ranges outside inferred function bodies. A completed optimized comparison
contained about 11 MiB of objects and recorded about 204,000 messages of the
same class.

The current inference is that Ghidra's GCC exception analysis is repeatedly
trying to reconcile C++ LSDA records with function boundaries while the
archive members are still relocatable and therefore lack their final linked
layout. `-O0` increases the object and exception-analysis population. Repeated
message formatting and disk writes then compound the analysis cost. This must
be tested rather than treated as a proven causal decomposition.

### Experiment 1: suppress repeated LSDA logging

Test an analysis policy that preserves the analyzer but suppresses, samples or
rate-limits repeated `LSDACallSiteTable` messages after recording a bounded
diagnostic summary. Do not simply discard the existence of the condition: the
attempt evidence should retain the total or sampled count, affected analyzer,
route and object population.

Compare the candidate against the canonical path using the same pinned source,
toolchain, route and treatment. Measure:

- Ghidra wall and CPU time;
- application-log bytes and write volume;
- peak resident memory and Ghidra-project bytes;
- function and program counts;
- normalized full and specific FID hashes and relationships; and
- packed and raw FID population results.

Logging suppression may become a default-path optimisation only if semantic
outputs are identical and wall time is neutral or lower. A different whole-file
FIDB digest alone is not a semantic failure because fresh Ghidra containers
carry per-run metadata.

### Experiment 2: optionally disable GCC exception analysis

Identify the exact registered Ghidra analyzer responsible for the LSDA work and
add a named, versioned analysis-policy experiment that disables it only for
relocatable archive members on the affected route. The policy must be explicit
in TOML and provenance; it must fail closed if the expected analyzer cannot be
identified. It must not silently affect linked images or unrelated targets.

Run a small MIPS oracle covering at least optimized and `-O0` Protobuf cells.
Compare the same timing, population, full-hash, specific-hash and relationship
evidence used for logging suppression. Also query both candidate databases
against fixed linked MIPS binaries to detect a change in useful matches.

If disabling the analyzer changes FID evidence, retain it only as an explicit
experimental treatment until the recall and precision effect is understood. If
it produces equivalent FID evidence and a representative speedup, qualify the
policy before considering it for the canonical relocatable-object path. The
existing analysis policy remains the rollback route throughout.
