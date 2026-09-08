# Documentation map

The root `README.md` is the short project entry point. This directory separates
stable contracts from operational procedures and historical research notes.

## Architecture

- [`architecture/pipeline.md`](architecture/pipeline.md) traces one build from
  reviewed request to sealed FIDB output.
- [`architecture/toolchains.md`](architecture/toolchains.md) defines portable,
  TOML-controlled toolchain packs and the external Apple boundary.
- [`architecture/lane-databases.md`](architecture/lane-databases.md) defines raw
  lane databases, query-compatible sublanes and experimental compaction.
- [`artifact-boundaries.md`](artifact-boundaries.md) defines what Git tracks,
  what retention preserves and what local state may be reconstructed.

## Validation

- [`validation/hash-discrimination.md`](validation/hash-discrimination.md)
  defines the Hash Discrimination Index, its evidence inputs and ablation
  requirements.
- [`../validation/README.md`](../validation/README.md) covers machine and
  ecological validation authorities and generated evidence.

## Operations

- [`operations/agent-runbook.md`](operations/agent-runbook.md) is the durable
  handoff and diagnostic guide for maintainers and agents.
- [`operations/retention.md`](operations/retention.md) defines dry-run-first
  evidence retention and garbage collection.
- [`operations/export.md`](operations/export.md) defines safeguarded portable
  database releases.
- [`../operations/README.md`](../operations/README.md) documents service
  operation, while
  [`../operations/RECOVERY_RUNBOOK.md`](../operations/RECOVERY_RUNBOOK.md)
  covers evidence-preserving incident recovery.

## Historical record

Documents under [`history/`](history/) preserve design reasoning and experiment
history. They are evidence, not current operating authority:

- `operator-workbench.md` — detailed accumulated operator notes;
- `unification-plan.md` — the completed recipe/malware unification design.

Personal chronological operator notes are local-only and ignored by Git.
Stable findings must be promoted into the relevant reviewed document before
they are relied upon by another operator or agent.

When historical prose conflicts with code, tests or current TOML, the reviewed
TOML and executable validation gates win.

## Authority and live state

- Human-reviewed TOML describes intent.
- Generated plans under `plans/*-materialized/` are derived projections and are
  guarded by drift tests.
- `plans/priority-queue.toml` orders admitted work but does not itself prove that
  a cell ran.
- `var/fidb-coordinator/ledger.sqlite3` is local mutable coordination state.
- Sealed artifacts and their digests are execution evidence.

See [`../plans/README.md`](../plans/README.md) for the plan-directory boundary.
Do not copy live status into stable documentation; obtain it from the control
panel, the queue doctor and the ledger-backed API.
