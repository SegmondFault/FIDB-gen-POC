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

