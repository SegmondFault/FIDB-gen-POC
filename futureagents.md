# Future-agent operating notes

This repository controls expensive, evidence-producing work on the Linux host
`reference-host`. Treat TOML as authority, SQLite as the durable coordinator ledger,
and `artifacts/runs/` as evidence governed by the explicit retention boundary.
A green unit test or resolution
preflight is necessary, but a real end-to-end canary is the execution boundary.

## Authority chain

The execution identity is assembled from separate reviewed layers:

1. `sources/*.toml` pins the upstream release, URL, size, and SHA-256.
2. `recipes/*.toml` binds that source identity to a fixed adapter and retained
   archive names. Recipes are declarative and must never contain shell commands,
   arbitrary flags, or free-form environment variables.
3. `src/fidb_poc/adapters.py` contains the reviewed executable build behavior.
   Add or change an adapter with focused tests and cross-target compilation
   canaries.
4. `toolchains/*.toml`, prepared pack state, and qualification records establish
   compiler provenance. `worker.toml` maps stable route IDs to those qualified
   packs and the correct Ghidra language/compiler pair.
5. Width and treatment TOML select applicable combinations. Materialized plan
   TOML freezes exact cells; queue TOML orders and admits them.

Never repair a runtime mismatch by weakening identity comparison. Correct the
authority that is wrong, regenerate the affected plans, and preserve the old
generation in the ledger.

## Sources and recipes

Prepared campaigns use the content-addressed cache at
`var/fidb-sources/downloads/`. Queue cells must pass this cache to the native
pipeline. A per-attempt `work/downloads/` directory is scratch, not the source
cache; allowing every cell to fetch upstream creates network dependence and was
the cause of the Readline block-01 failures on 2026-09-03.

Before materialization, require all of the following:

- source status is cached and checksum-verified;
- recipe name, version, URL, and SHA-256 match the source pin;
- the fixed adapter produces every declared static archive;
- target-family and oldest compiler-generation canaries pass; and
- no command or unbounded caller input has entered recipe TOML.

Project-specific accommodations belong in the fixed adapter and its tests. The
current gettext, GMP, and Readline exceptions are documented in
`recipes/README.md`.

## Route resolution lessons

- A Ghidra `LanguageID` ending in `:default` does not imply that
  `CompilerSpecID=default` exists. Android x86 and x86-64 use compiler spec
  `gcc` with the current Ghidra languages.
- Tool output strings are not canonical identities. The reviewed equivalence
  `Intel 80386` ↔ `Intel i386` is accepted only by the artifact validator;
  do not introduce fuzzy substring matching.
- Versioned routes and base routes must resolve through the same canonical
  route loader. The queued toolchain material digest, qualification digest,
  executable paths, target, and Ghidra pair must match runtime resolution.

Run both checks after any source, recipe, toolchain, worker-route, width, or
materialized-plan change:

```sh
uv run fidb-poc queue preflight --project-root . --queue plans/priority-queue.toml
uv run fidb-poc queue resolve-preflight --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3
```

The second command must report every active job passed and zero failure classes.

## Canary boundary

A useful canary reaches source acquisition, extraction, compilation, archive and
object validation, Ghidra import/analysis, FID population, packed FIDB and FIDBF
export, final validation, provenance sealing, and atomic publication. It must use
the production `GHIDRA_HEADLESS` path and JVM limits from
`~/.config/fidb-factory/library-local-worker.env`; a manually launched worker
without that environment is not representative.

`plans/materialized/canaries/c-android-x86-sqlite-readline.toml` covers both affected libraries,
Android x86 32/64, and NDK r27d/r29 base/versioned identities. Its queue remains
disarmed in Git. The repaired canary completed 8/8 cells on 2026-09-03 in the
isolated ledger `var/fidb-canary/ledger-v2.sqlite3`.

The later campaign-runtime recovery canary is
`plans/materialized/canaries/c-failure-recovery-2026-09-04.toml`; its queue is
disarmed and its isolated ledger is
`var/fidb-canary/failure-recovery-2026-09-04.sqlite3`. It completed 6/6 real
cells on 2026-09-04, covering the six terminal campaign failure classes:

- safe relative archive symlinks for Zstandard;
- preserved archive mtimes for nghttp2's generated Autotools files;
- large OpenSSL native-manifest CSV fields;
- GMP host generators under a Windows cross route;
- bounded Windows build paths for gettext/Wine probes; and
- header-based AMD64 COFF object validation for PCRE2.

The cells took 46.2, 32.7, 518.8, 117.7, 162.3 and 41.0 seconds respectively.
Before any production recovery, the exact active generation also resolved
2,046/2,046 cells across 37 routes and six treatments with zero failures.

## Queue transitions and recovery

Pause first, disarm second, then verify no leases or active workers before
changing an active generation. Never clear the ledger to make a plan fit.
Synchronizing a corrected generation deactivates superseded jobs but retains
their attempts and events. Preserve all `artifacts/runs/` attempt directories.

For unchanged identities, use the supported bounded transition:

```sh
uv run fidb-poc queue requeue-failed --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3 --batch BATCH_ID \
  --expected-count N --reason "reviewed reason"
```

Do not requeue jobs after their route or plan identity changes. Synchronize the
new generation instead and record why the inactive historical generation was
superseded. The authority-failure circuit breaker pauses claims after five
terminal failures in one authority class; investigate it rather than repeatedly
resuming.

The guarded transition accepts either no active admission or an admission for
the exact selected batch. It rejects an admission for any other batch. This
permits recovery of a paused partially completed block without clearing its
untouched rows or losing the block boundary. On 2026-09-04, 21 OpenSSL failures
in chunk 001 were requeued this way; 24 sealed completions and 21 untouched jobs
were left unchanged, and the returned job-ID digest was retained in the ledger.

Do not classify every Java `OutOfMemoryError` as heap exhaustion. The 2026-09-04
OpenSSL run had ample host memory and a 4 GiB heap but reached about 470 tasks in
individual worker cgroups. Under `TasksMax=512`, Ghidra failed with `unable to
create native thread`. The reviewed local and remote worker units now use the
bounded `TasksMax=1024` ceiling. Inspect `TasksCurrent`, `TasksMax`,
`MemoryCurrent`, `MemoryPeak`, host available memory and the exact exception
before changing heap or concurrency.

## Time-aware campaign

`plans/c-top10-nonapple-width-v2-queue-policy.toml` is the stable operational
input to `fidb-poc auto-batches`. The generated candidate remains disarmed under
`plans/auto-materialized/`; the reviewed active copy is
`plans/priority-queue.toml`. The current policy creates 23 route/treatment-coherent
chunks, targets about 60 minutes, caps the central estimate at 85 minutes, and
keeps all six treatments for a library/route together.

The window is `00:00–05:30 Europe/Luxembourg`. `chain_batches=true` admits the
next ordered chunk only after the current one drains and only while the window
is open. `finish_started_batch=true` lets a started chunk finish after 05:30.
Manual `queue start-block` admits exactly one chunk outside the timer.

One-day operational extensions belong in `[[schedule.date_overrides]]` TOML
tables, not in a permanent edit to the normal window. A named local date may
override `start`, `stop_claiming` and `hard_cutoff`; after that date, evaluation
automatically returns to the normal schedule. Keep `hard_cutoff` absent when an
already-started chunk must be allowed to drain.

Regenerate only after reviewing changed authorities:

```sh
uv run fidb-poc auto-batches --project-root . --check
uv run fidb-poc auto-batches --project-root . --write
```

Generation cannot arm, synchronize, or execute work. Arming the active queue is
a separate, small commit. Before leaving a scheduled run unattended, verify the
queue is armed and unpaused, exact resolution passes, resource gates pass, and
all 20 configured worker services are active.

## Rollback

Stop new claims with `queue pause`, commit `armed=false`, synchronize it, and let
or deliberately stop any already leased cells according to the incident. Revert
operator/configuration commits with new `git revert` commits; do not rewrite Git
history or delete ledger rows. Resynchronizing the previous reviewed queue makes
the replacement generation inactive while retaining both generations' evidence.

## Verification discipline

Use focused tests while iterating, then run the complete suite before handoff:

```sh
uv run python -m unittest discover -s tests
```

Report the commit IDs, exact queue counts, schedule and timezone, worker-service
count, preflight totals, canary scope/result, and any retained failed generation.
Do not describe a queue as ready merely because its TOML parses.

## Post-drain retention

Read `RETENTION.md` before changing attempt cleanup. The authority is
`retention/policy.toml`; holds are reviewed in `retention/holds.toml`. Never add
an ad-hoc `rm` to a worker or nightly script.

The order is fixed: terminal queue, content-addressed dry-run, bounded apply if
eligible, then one worker recycle per drain-session ID. Queue completion is the
trigger even when it occurs outside the configured claim window. A deferred
apply must not defer worker recycling: stale Ghidra JVM state was observed
retaining about 38 GiB across 20 idle workers. Recycling releases it without
host-wide cache or swap manipulation. The replacement worker must record the
TOML-controlled secondary RSS/JVM audit before queue synchronisation; do not
replace that cross-process check with `gc.collect()`, which cannot unload an
embedded JVM. A recycled worker with a terminal ledger parks before queue
resolution and wakes on durable pending work; preserve that cheap idle path or
the pool will immediately rebuild the memory it just released.

Successful attempt scratch is ineligible until the queue-to-lane importer has
emitted a valid relationship-complete receipt. The importer is not implemented,
so current successful attempt directories remain whole. Failed retries may be
reduced only through a verified evidence bundle; different failure fingerprints,
holds, symlinks and uncertain ownership remain quarantined.

The first production dry-run selected 973 actions and 257,415,636,119 apparent
bytes but estimated 1,041.553 seconds, above the 600-second automatic ceiling.
It was therefore not applied. Do not raise that ceiling merely to clear the
backlog; review the exact plan and perform the initial collection manually if
the evidence set is acceptable.
