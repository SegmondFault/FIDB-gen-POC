# Retention and garbage collection

Queue retention is controlled by `retention/policy.toml`; explicit preservation
holds live in `retention/holds.toml`. SQLite remains the runtime ledger. A
collector plan is a content-addressed statement of what was verified, what is
protected, what is quarantined, and which exact directories may be removed.

## Safety boundary

The collector is always dry-run-first. A plan binds the policy digest, ledger
generation and attempt history, action list, byte counts, preservation set and
quarantine set. Apply requires the exact plan digest, recomputes the plan, and
fails if the ledger, files or policy changed. It also refuses to apply while an
attempt is leased or running. Symlinks and non-regular tree members are
quarantined rather than followed.

Successful final attempts remain whole until the future queue-to-lane importer
emits a relationship-complete receipt bound to the job, attempt root and cell
seal SHA-256. No such importer exists yet, so the current policy removes no
successful attempt scratch. Even after a valid receipt, only the policy's
attempt-relative `prune_after_receipt` paths are candidates; the FIDB, FIDBF,
seal and lane evidence remain.

For a failed job, the latest attempt becomes the representative evidence
bundle. Earlier retries are included only when their normalized failure
fingerprint is identical. A different fingerprint is quarantined and kept
whole. The bundle is written and its selected files are re-hashed before source
attempt directories are removed. Operator holds always win.

Machine-validation runs use the same collector with a separate
`machine-validation` scope. A run is eligible only when `status.json` and the
terminal report agree that every expected work unit completed with no execution
failure. The collector hashes every unit result, truth map, exported query
signature file and retained composite binary. Those files, the report and the
run logs remain in place. Only TOML-selected direct-child `worker-*` directories
are disposable; they contain reconstructed build trees and per-process Ghidra
state. Failed, interrupted, incomplete or structurally inconsistent validation
runs are quarantined whole.

This boundary deliberately preserves the inputs needed to replace the mistaken
five-signature library threshold with exhaustive per-hash analysis. Do not add
`units/`, `reference-index.sqlite3`, reports, truth maps, query signatures or
composite binaries to validation scratch without a newer, verified downstream
receipt.

## Commands

All commands run from the project root. Status is read-only:

```sh
uv run fidb-poc retention status --project-root .
```

Create and inspect a durable dry-run:

```sh
uv run fidb-poc retention plan --project-root .
```

Apply only the exact current digest printed by the plan:

```sh
uv run fidb-poc retention apply --project-root . \
  --plan-digest PLAN_SHA256
```

`fidb-poc retention auto` follows `[automation]` in the policy. Workers call
the same operation after a terminal queue, including when the last admitted
block drains after the claim window has closed. The default automatic ceiling
is 600 seconds. Plans above it remain available for manual review and are not
applied automatically.

A measured-complete machine-validation runner invokes the same operation with
trigger `machine-validation-complete` and scope `machine-validation`. The
terminal report is durable before the runner lock is released. Cleanup failure
is recorded as `failed-safely` in the run's `retention.json` and cannot change a
successful scientific report into a failed run. The queue-drained trigger keeps
the broader `all` scope.

The control panel exposes the same status and guarded operations under
**Operations → Retention**. The Matrix shows retention as the terminal campaign
stage.

## Worker memory

Queue completion and process completion are different events. Long-lived
workers may retain imported Ghidra classes and JVM heap after their last job.
After post-drain retention has completed or safely deferred, each worker
replaces itself once for that drain-session ID. This releases JVM memory while
leaving a low-memory worker ready for a later queue. The session marker prevents
an idle restart loop. Garbage collection never runs `drop_caches`, `swapoff` or
another host-wide memory command.

Process replacement is the cleanup mechanism; the fresh process then performs
a secondary audit. The old process hands over its current RSS and embedded-JVM
state through one-use environment values. Before queue synchronisation or JVM
startup, the replacement records its RSS and confirms that pyghidra has not
started a JVM. Per-worker reports are written beneath the ignored
`var/fidb-retention/memory-audits/` tree and aggregated in **Operations →
Retention**. `[memory_cleanup]` in `retention/policy.toml` enables this check and
sets the fresh-worker RSS warning threshold. A warning is evidence for review;
it does not invoke host-wide memory controls or delete run evidence.

After a successful audit, a terminal worker parks before the expensive queue
resolution path and performs only the configured lightweight SQLite wake check.
It resumes normal queue loading when active queued/leased/running work appears.
This prevents twenty clean replacement processes from immediately rebuilding
the same terminal plan state and consuming several gigabytes again.

## First production dry-run

On 2026-09-04 the initial read-only scan took 82.39 seconds. It verified 1,722
successful attempts and selected 973 failure-bundle actions spanning 2,239
attempt directories. The selected trees contained 257,415,636,119 apparent
bytes. The conservative initial apply estimate was 1,041.553 seconds, so the
600-second automatic ceiling correctly deferred this accumulated backlog. No
file was removed. Incremental nightly plans are expected to be smaller, but
their measured scan/apply records—not that expectation—control automation.

## Rollback

Set `enabled = false` and `worker_action = "none"` in
`retention/policy.toml`, then restart workers, to disable post-drain behavior.
Set `validation.automatic_after_terminal_run = false` to keep validation
retention available only through a manual dry-run and exact apply.
Revert the retention commits to remove the feature without changing the queue
ledger. Plans and bundles are additive ignored runtime evidence and can remain.

An applied deletion cannot reconstruct disposable scratch. This is why success
scratch is gated by a relationship-complete lane receipt and failure deletion
is gated by a verified concise bundle. Preserve filesystem backups when whole
failed build trees may later be required for research.
