# Plan authority boundaries

This directory contains both reviewed planning inputs and deterministic
projections. Their roles are intentionally different.

## Reviewed authority

Top-level TOML files are human-reviewed inputs unless their header says
otherwise. Important examples include:

- `priority-queue.toml` — ordered admission authority;
- `c-top10-nonapple-width-v2-queue-policy.toml` — stable C10 generator input;
- `auto-batching.toml` and `batch-window.toml` — time-block policy;
- `validation-schedule.toml` — validation admission policy;
- coverage, baseline and recovery plans — explicit requested work.

Review schema versions, pinned digests and disarmed/armed state in the file
itself. File placement never implies that work is safe to execute.

## Generated projections

- `materialized/` contains deterministic campaign plans and manifests.
- `auto-materialized/` contains time-sized queue chunks.
- `validation-materialized/` contains cohort-validation plans and manifests.

Do not edit these files by hand. Regenerate them through the owning command and
run its `--check` or equivalent drift gate. Generated plans may be committed
because they make review and exact re-execution possible; their generator input
and digest remain the authority.

## Mutable state is elsewhere

The queue ledger under `var/` records leases, attempts and results. Sealed output
under `artifacts/` records execution evidence. Neither is a plan, and neither
becomes source authority by being present on disk.
