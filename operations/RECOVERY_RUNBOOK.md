# Queue incident and recovery runbook

This runbook covers failures in the TOML-authoritative, SQLite-coordinated local
library factory on `reference-host`. It preserves completed artifacts, attempts,
stage spans, failure evidence and queue ordering. It never uses direct SQLite
updates.

## First response

Collect a coherent read-only snapshot before changing anything:

```sh
uv run fidb-poc queue doctor \
  --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3 \
  --include-inactive \
  --services > incident.json
```

`queue doctor` does not pause, synchronize, claim, requeue or execute work. It
opens the ledger with `mode=ro`, reports current and historical failures, groups
exact current error fingerprints, compares the installed worker unit with the
repository unit, and uses only `systemctl --user show` when `--services` is
requested. Its recovery candidates include the exact failed count and SHA-256
of the ordered job IDs.

If the incident is not systemic, let unrelated live cells finish while the
report is reviewed. If failures share one cause or new claims could destroy
useful time, stop new claims immediately:

```sh
uv run fidb-poc queue pause --reason "incident review: SHORT_DESCRIPTION"
```

Pause changes the durable coordinator gate. Editing `armed` in TOML alone does
not stop workers which already loaded the old queue. Pause does not terminate a
leased cell.

## Recovery state machine

Use these phases in order:

1. **Collect** — run `queue doctor`; retain the report with the incident notes.
2. **Contain** — pause the ledger if the failure is systemic.
3. **Disarm** — set `armed = false` in the active queue TOML and synchronize it.
4. **Drain** — wait until global leased/running counts are zero.
5. **Classify** — identify authority, adapter, artifact, analysis, resource or
   service failure from the failed stage and exact exception.
6. **Repair** — change the narrowest reviewed authority or implementation and
   add a regression test.
7. **Resolve** — re-resolve the exact active generation without execution.
8. **Canary** — prove the affected libraries and route classes end to end in an
   isolated ledger.
9. **Requeue** — use the bounded transition with the doctor's exact count.
10. **Rearm** — make the small reviewed TOML change, synchronize, then resume.
11. **Observe** — require formerly failing cells to seal before unattended work.
12. **Retain** — leave attempt evidence and `artifacts/runs/` under the retention
    policy; never clean an incident with ad-hoc deletion.

The requeue phase is unavailable unless the queue is disarmed and paused, no
job has a live lease, the selected batch is active, and any durable admission
belongs to that same batch. `queue doctor` reports every unmet guard.

## Authority and execution gates

Run both gates after changing a source, recipe, adapter, toolchain, route,
treatment, width authority or materialized plan:

```sh
uv run fidb-poc queue preflight \
  --project-root . \
  --queue plans/priority-queue.toml

uv run fidb-poc queue resolve-preflight \
  --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3
```

The first reports schedule and host resource gates. The second invokes the same
canonical runtime resolver used by workers across every exact active job. It
does not compile and does not start Java. A production generation is not ready
unless it reports all selected jobs passed and zero failure classes.

For a bounded investigation, repeat `--batch BATCH_ID`. The final gate before
recovery must still cover the entire active generation whenever shared
authority changed.

## Failure classification

| Evidence | Likely boundary | Required check |
|---|---|---|
| `unknown route`, queued identity mismatch, or `authority-resolution:*` | Canonical route/toolchain authority | Full `resolve-preflight`; compare queued material and qualification digests, executable paths, target, Ghidra language and compiler spec |
| Download, connection or checksum failure | Source acquisition | Confirm the content-addressed source exists under `var/fidb-sources/downloads/` and matches its pin; do not add per-cell network fetching |
| `database is locked`, `SQLITE_BUSY` or a lease-heartbeat lock failure | SQLite write contention | Preserve the attempt; inspect concurrent coordinator writers and timeout evidence; never requeue while other leases remain live |
| Configure/CMake/Make failure isolated to one project | Fixed recipe adapter | Reproduce with the exact source, route and treatment; patch `adapters.py`, add focused tests and canary oldest compiler/target families |
| Unsafe link or extraction-path rejection | Archive boundary | Preserve only safe relative archive links; never weaken containment for an upstream layout |
| ELF/COFF/Mach-O or architecture mismatch | Artifact validation | Read binary headers; tool output strings are advisory and must not replace exact header validation |
| `OutOfMemoryError: unable to create native thread`, `pthread_create`/`EAGAIN` | Worker task/PID ceiling | Compare `TasksCurrent` with `TasksMax` and host memory before changing heap |
| Java heap-space failure with TasksCurrent below its ceiling | JVM heap or analysis shape | Record `MemoryCurrent`, `MemoryPeak`, heap limit, object count and analysis stage; reproduce with one worker |
| Many workers fail together at the same stage | Shared authority or host resource | Pause; inspect the circuit-open event, resource preflight and worker-unit drift before retrying |
| Idle workers retain tens of GiB after drain | Embedded JVM lifetime | Verify post-drain recycle and memory audit; do not use host-wide cache or swap manipulation |

Do not repair an identity mismatch with fuzzy comparison. The only reviewed
tool-name equivalence is the explicit artifact-validator mapping already in the
code. Do not raise memory, task or worker ceilings solely because a Java error
mentions memory.

## Repairs established on 2026-09-03 and 2026-09-04

These are regression boundaries, not generic workarounds:

| Failure | Fix and proof |
|---|---|
| 240 versioned width routes were unknown at runtime | Base and versioned routes now use one canonical route loader |
| 204 base routes disagreed with queued toolchain identities | Runtime validates the frozen toolchain material/qualification identity in the same shape used by materialization |
| 444 cells failed before compilation in about ten seconds | `authority_failure_threshold = 5` pauses new claims after five same-class authority failures |
| A syntactically valid queue reached runtime with incompatible authority | `resolve-preflight` re-resolves all 2,046 exact active cells; the repaired generation passed 2,046/2,046 across 37 routes and six treatments |
| Readline cells depended on a fresh upstream download inside each attempt | The native pipeline receives the checksum-verified content-addressed source cache |
| Android x86 Ghidra language IDs ended in `:default` but rejected compiler spec `default` | Android x86 and x86-64 routes use Ghidra compiler spec `gcc` |
| Zstandard archives contained legitimate relative symlinks | Extraction preserves safe relative links while retaining containment |
| nghttp2 Autotools files appeared stale after extraction | Archive extraction preserves source mtimes |
| OpenSSL native-object manifests exceeded the default CSV field limit | The fixed manifest reader accepts the measured bounded field size |
| GMP Windows cross-build attempted target executables as build tools | Host generators are built and run with the build-host toolchain |
| gettext Windows probes used paths too long for the exercised Wine/toolchain route | The adapter uses a bounded build path without changing artifact identity |
| PCRE2 AMD64 COFF objects were rejected from ambiguous `file(1)` wording | The validator reads COFF headers and the reviewed `Intel 80386`/`Intel i386` equivalence remains explicit |
| OpenSSL Android ARM64/O0 failed with `unable to create native thread` at 512 and 1,024 tasks | A one-worker canary observed 1,103 tasks and sealed under `TasksMax=2048`; the 4 GiB heap and 8 GiB hard memory limit were unchanged |
| Twenty simultaneous worst-shape cells could exceed 94 GiB despite a twenty-worker profile ceiling | Recovery used 14 active services; the queue profile remains a ceiling, not an instruction to start every unit |
| Drained workers retained embedded JVM memory | Post-drain retention recycles each worker once, records pre/post RSS and JVM state, then parks the fresh process until durable work returns |
| A single nghttp2 recovery reached configure correctly but its lease heartbeat lost a transient SQLite write race | Heartbeats retry only SQLite `BUSY`/`LOCKED` contention for a bounded fraction of the lease; other database errors remain terminal |

The six-cell runtime canary is
`plans/c-failure-recovery-2026-09-04-canary-queue.toml`. It covers Zstandard,
nghttp2, OpenSSL, GMP, gettext and PCRE2 and completed all six real pipelines.
The high-object-count proof is
`plans/c-openssl-tasksmax-2048-2026-09-04-canary-queue.toml` and completed in
458.379 seconds, including 428.501 seconds of Ghidra analysis.

The final one-cell C10 proof is
`plans/materialized/canaries/c-nghttp2-aarch64-gcc13-os-recovery.toml`. It
sealed the exact AArch64 GCC 13 `Os` identity before the guarded production
requeue; the production cell then sealed on attempt 5. When a fix changes
loaded Python execution code, use a fresh canary/worker process—an already
running worker does not acquire that fix from the worktree.

## Worker-unit verification

The repository unit is
`operations/fidb-library-local-worker@.service`; the installed copy is
`~/.config/systemd/user/fidb-library-local-worker@.service`. `queue doctor`
reports both SHA-256 digests and the effective `CPUQuota`, `MemoryHigh`,
`MemoryMax` and `TasksMax` text from each copy. A mismatch means repository
changes are not active.

After reviewing a repository unit change, installation remains deliberate:

```sh
install -m 0644 operations/fidb-library-local-worker@.service \
  "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
```

Do not restart a running pool merely to make the copies match. Pause and drain
first unless an emergency stop is justified. Inspect live counters with:

```sh
systemctl --user show 'fidb-library-local-worker@1.service' \
  -p ActiveState -p SubState -p TasksCurrent -p TasksMax \
  -p MemoryCurrent -p MemoryPeak
```

For a pool-wide JSON snapshot, use `queue doctor --services`.

## Evidence-preserving requeue

After the repair, full resolution preflight and isolated canary pass, collect a
fresh doctor report. Copy its exact candidate count into the guarded command:

```sh
uv run fidb-poc queue requeue-failed \
  --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3 \
  --batch BATCH_ID \
  --expected-count EXACT_COUNT \
  --reason "repair, regression test and canary references"
```

The transition clears only the active job's terminal state. It preserves every
attempt and stage row, appends per-job and batch recovery events, and returns
the ordered job-ID digest. If count, batch, admission or safety state changed,
it fails closed. Never substitute an SQLite `UPDATE`.

Rearm in a separate commit. Synchronize the exact reviewed queue, rerun
resolution preflight, resume the ledger, and observe the formerly failing class
through provenance seal and atomic publication before leaving the run alone.

## Rollback and retention

Rollback uses new `git revert` commits and resynchronization of the previous
reviewed queue. It never rewrites Git history or deletes ledger rows. Preserve
all attempt directories until `docs/operations/retention.md` and `retention/policy.toml` classify
them. Successful scratch is not disposable until the future lane importer has
written a relationship-complete receipt. Failed retries are collapsible only
when the retention collector proves identical failure fingerprints and retains
the final concise evidence bundle.
