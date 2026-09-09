# Maintainer and agent entrypoint

This repository controls expensive, evidence-producing work. Read
[`docs/operations/agent-runbook.md`](docs/operations/agent-runbook.md) before
changing execution authorities or operating a campaign. During an incident,
follow [`operations/RECOVERY_RUNBOOK.md`](operations/RECOVERY_RUNBOOK.md).

## Non-negotiable boundaries

- Treat reviewed TOML as intent, the coordinator SQLite ledger as mutable
  execution state, and sealed artifacts as evidence. Do not substitute one for
  another.
- Never edit the coordinator database directly. Use the supported queue,
  recovery, retention and migration commands.
- Do not arm, start, resume, requeue or delete work unless the current task
  explicitly authorises that state change.
- Preserve completed attempts and failure evidence until the retention policy
  proves they are disposable. Run retention in dry-run mode first.
- Do not weaken identity, digest, format or provenance checks to make a cell
  pass. Correct the narrowest invalid authority or implementation instead.
- Keep default-path changes wall-time neutral or faster, supported by a
  representative benchmark. Slower diagnostics must remain opt-in.

## Change workflow

1. Begin with read-only status, doctor or preflight commands.
2. Identify the authoritative input and the smallest affected boundary.
3. Make focused changes with regression tests and sensible atomic commits.
4. Regenerate deterministic authorities through their supported commands;
   never hand-edit generated digests or execution evidence.
5. Run focused tests, then the complete backend and control-panel checks.
6. For execution changes, require resolution preflight and a representative
   end-to-end canary before production admission.
7. Record new reusable failure and recovery knowledge in the detailed agent or
   recovery runbook, not in personal chronological notes.

## Publication boundary

`.codex/`, `.agents/`, private development notes, generated databases,
artifacts, work trees and runtime state are not source deliverables. Preserve
Git authorship and [`CONTRIBUTORS.md`](CONTRIBUTORS.md) when publishing.

The detailed runbook contains the canonical commands, authority chain,
qualification gates, known failure classes, recovery transitions and campaign
handoff state. This file is intentionally only the stable entrypoint.
