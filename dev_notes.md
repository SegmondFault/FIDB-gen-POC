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

## OpenSSL linker-sensitivity investigation

Status: proposed bounded study. The existing C10 reference-form result proves
that pre-link archive members and post-link images are materially different
reference populations, but it does not measure how many signatures change
between linker families or linker policies.

### Question

Measure how much the linker changes Ghidra FID evidence when the compiler,
source, target, treatment and input object files are held fixed. Use OpenSSL
3.5.8 first because its reviewed C recipe and existing C10 evidence make it a
large, relevant test case without introducing C++ exception-analysis effects.

Keep these quantities separate:

- **signature survival:** whether the same source function retains its full
  hash, specific hash and relationship evidence after linking;
- **population change:** signatures or functions added, removed, folded or
  synthesized by the link;
- **detection effect:** marginal correct-owner matches, precision, recall,
  false-positive rate and noisy-hash contribution; and
- **cost:** extra link, Ghidra, storage and query work.

The C10 archive-to-linked change of 66.86% to 91.46% recall is a detection
effect, not a claim that 24.60% of hashes changed. Set overlap alone is also
insufficient because duplicate and noisy hashes can hide which function
changed; comparison must use symbol identity and link-map evidence where
available.

### Preliminary OpenSSL bellwether

A read-only comparison was run against retained signature evidence while the
production campaign continued. It performed no compilation, linking or Ghidra
analysis and used idle-class I/O plus the lowest CPU scheduling priority.

The comparison selected OpenSSL 3.5.8, Linux x86-64, GCC 12 and `baseline_o2`.
It joined the archive-member and linked-image signature ledgers by function
name, then restricted the hash-survival calculation to 12,064 names having
exactly one record on each side:

| Measure | Unchanged | Changed |
| --- | ---: | ---: |
| Full hash | 12,042 / 12,064 (99.8176%) | 22 / 12,064 (0.1824%) |
| Specific hash | 11,942 / 12,064 (98.9887%) | 122 / 12,064 (1.0113%) |
| Both hashes | 11,942 / 12,064 (98.9887%) | 122 / 12,064 (1.0113%) |

The archive ledger contained 12,156 records and the linked ledger 12,155. It
had one archive-only function name and no linked-only name. As a second view,
99.7395% of the linked population's unique full hashes and 98.7158% of its
unique specific hashes were also present in the archive population.

This bellwether suggests that raw hash mutation was not the main cause of the
large C10 archive-to-linked detection difference. Linked-image grouping,
relationships and FID decision context are stronger candidate explanations.
It also moves the expectation for ordinary non-LTO, same-mode linker-family
variation toward the lower end of the planning range.

This is not formal linker-sensitivity evidence. The archive ledger came from
an earlier build with the same declared identity rather than a retained proof
that both sides used byte-identical object files; names were not qualified with
the link map; and both populations used the existing linker path rather than a
controlled `ld.bfd` versus `lld` pair. Preserve the four-cell same-object study
below as the required experiment.

### First bounded matrix

Compile one pinned x86-64 OpenSSL route and treatment once, seal its archive,
then derive all link variants from those exact object bytes:

1. GNU `ld.bfd`, canonical whole-archive shared image with symbolic binding;
2. LLVM `lld`, the same shared-image policy;
3. `ld.bfd`, a reviewed executable/PIE-shaped image with a neutral entry stub;
4. `lld`, the same executable/PIE-shaped policy.

The shared-image policy should initially match the qualified validation route:
`-shared`, `-nostdlib`, `--whole-archive` and `-Bsymbolic`. The executable-shaped
variant must record unresolved symbols and target selection rather than
silently dropping archive members. Do not execute target binaries.

Only after this four-cell comparison should the study consider section garbage
collection, identical-code folding, relaxation or static-versus-dynamic
binding. LTO is a separate compiler-plus-linker treatment because it cannot
reuse the same ordinary object files.

### Evidence and reproducibility

For every variant retain:

- exact source, route, compiler, treatment and sealed input-object identity;
- linker path, family, version and binary digest;
- normalized link command, link map, unresolved-symbol audit and output digest;
- Ghidra version, language/compiler spec and analysis-policy identity;
- per-function symbol identity, full hash, specific hash, size and relationships;
- unchanged, changed, missing, new, folded and synthetic-function counts;
- marginal unique hashes and correct-owner detection contribution; and
- link/Ghidra/query wall time, CPU time, peak RSS, scratch, project and FIDB
  bytes.

Store the compact comparison and a human-readable receipt as tracked evidence;
keep heavy binaries, Ghidra projects and generated databases under the existing
ignored artifact boundary.

### Planning hypotheses and expansion gate

Before measurement, expect same-mode `ld.bfd` versus `lld` changes to cluster
in functions containing calls, address materialization, thunks or
architecture-specific relaxation. For ordinary non-LTO OpenSSL C code the
working hypothesis is a low-single-digit percentage of full hashes, with a
wider uncertainty band of roughly 1–10%. Changing the output shape or enabling
garbage collection/folding may affect roughly 5–20% of the observable
population, while LTO can be substantially larger. These are planning ranges,
not findings or acceptance thresholds.

Expand across compiler versions, treatments and targets only when a variant
adds meaningful marginal validated coverage for acceptable wall time and
storage. Treat linker identity as a derived representation axis, not as an
automatic multiplication of every compilation cell. The current canonical
link path remains available as the rollback route.
