# Future-agent operating notes

This repository controls expensive, evidence-producing work on the Linux host
`reference-host`. Treat TOML as authority, SQLite as the durable coordinator ledger,
and `artifacts/runs/` as evidence governed by the explicit retention boundary.
A green unit test or resolution
preflight is necessary, but a real end-to-end canary is the execution boundary.

The operational recovery procedure is
[`operations/RECOVERY_RUNBOOK.md`](operations/RECOVERY_RUNBOOK.md). Start every
incident with the read-only queue doctor; do not reconstruct recovery SQL from
memory:

```sh
uv run fidb-poc queue doctor --project-root . \
  --state var/fidb-coordinator/ledger.sqlite3 \
  --include-inactive --services
```

The report contains exact current failure counts and fingerprints, ordered
failed-job digests, live-work and requeue guards, installed worker-unit drift,
recent failed stages and evidence-linked next commands. It performs no queue
transition and starts no build or JVM.

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

The final C10 recovery used the narrower
`plans/materialized/canaries/c-nghttp2-aarch64-gcc13-os-recovery.toml` canary.
The production `nghttp2-1.70.0:linux-aarch64-gcc-13:optimization_os` cell had
three historical Autotools mtime failures and one SQLite heartbeat-contention
failure. The exact isolated canary sealed with preserved archive mtimes; the
production job was then requeued through the guarded transition and sealed on
attempt 5. C10 ended at 2,046 complete, zero failed, zero queued. The queue was
paused and disarmed afterwards. Preserve all five production attempts.

Lease heartbeats now retry only transient SQLite `BUSY`/`LOCKED` contention
inside a bounded window. Do not broaden that retry to non-lock database errors:
those must still fail visibly. A worker process loaded before an extractor or
adapter repair still contains the old Python implementation; recycle it before
using the repaired path, even if tracked files are already correct.

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
OpenSSL run had ample host memory and a 4 GiB heap. The Android ARM64/O0 cell
imports 1,129 objects and failed with `unable to create native thread` under
both the former 512 and 1,024 task limits. The isolated one-worker canary at
`plans/c-openssl-tasksmax-2048-2026-09-04-canary-queue.toml` observed 1,103
live tasks and completed all stages in 458.379 seconds under `TasksMax=2048`;
Ghidra analysis took 428.501 seconds and the systemd memory peak observed during
sampling was about 5.43 GiB under the unchanged 8 GiB limit. The reviewed local
and remote worker units therefore use the bounded 2,048-task ceiling. Inspect
`TasksCurrent`, `TasksMax`, `MemoryCurrent`, `MemoryPeak`, host available memory
and the exact exception before changing heap or concurrency.

The 94 GiB production recovery resumed with 14 active service instances, not
all 20 allowed by the queue ceiling. Fourteen times the measured 5.43 GiB
worst-cell peak plus the host baseline remains bounded; twenty simultaneous
worst cells would exceed available physical memory. The exact formerly failing
production job (`android-arm64-ndk-r27d-clang-api21`, `optimization_o0`) then
sealed on attempt 6 under the 2,048-task unit. Treat 20 as the profile's maximum,
not a requirement to start every unit for every library shape; record the
actual active-service count alongside the named profile.

### Dated regression registry

The recovery runbook records every failure repaired during the first top-ten
campaign. Future agents must preserve these boundaries:

- canonical base/versioned route resolution and exact material identity;
- full-generation execution-resolution preflight and the five-failure circuit
  breaker;
- the shared content-addressed source cache rather than per-cell downloads;
- Android x86/x86-64 Ghidra compiler spec `gcc`;
- safe relative Zstandard links and preserved nghttp2 source mtimes;
- bounded OpenSSL manifest CSV fields;
- GMP build-host generators, bounded gettext Windows paths and header-based
  PCRE2 AMD64 COFF validation;
- measured `TasksMax=2048`, fourteen-service worst-shape recovery concurrency,
  and unchanged heap/memory guardrails; and
- post-drain JVM recycle, memory audit and cheap terminal worker parking.

Run the doctor's diagnostic rules and the cited regression canaries before
changing any of these. A passing build for one target is not permission to
remove a cross-target accommodation.

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

## C80 programme and mandatory cohort gate

The long-range programme is
`campaigns/c80-four-source-n80-v1.toml`. It freezes the published four-source
N80 research ranks 1–276 into 28 disarmed cohorts. Do not confuse these ranks
with the separate screened `sources/c-top30-v1.toml` calibration ranking, and
do not call every research row a C library. The programme may be inspected
with `fidb-poc campaign-programme --project-root .`; that command is read-only.

For every future cohort, follow this order:

1. screen candidate identity and retain exclusion/alias reasons;
2. add and verify exact source pins;
3. author command-free fixed recipes and dependency pins;
4. instantiate the 16-route O2 edge set from
   `qualification/c-cohort-template.toml` as a cohort-specific authority;
5. inspect `fidb-poc qualification status --project-root .`;
6. execute that exact qualification and require its current seal;
7. build the measured time projection and generate a disarmed short-chunk
   queue candidate;
8. verify the embedded seal and exact cell identities;
9. run the full-path compilation/Ghidra/publication canary; and
10. admit/arm separately, then retain terminal evidence and recycle workers.

`fidb-poc auto-batches` and the batch materializer reject unsealed cohort
authorities. A seal unlocks only queue candidate generation. It does not edit
`plans/priority-queue.toml`, synchronize the ledger, start workers or arm the
queue. If evidence is stale, preserve it and use the explicit `--restart-stale`
path; never delete or rewrite it. The complete rationale and rollback boundary
are in `campaigns/README.md` and `qualification/README.md`.

## C11–C20 staging

`coverage/c-top20-width-study.toml` and `sources/c-top20-v1.toml` preserve the
same provisional ranking method through global ranks 11–20. Their ten new
archives are checksum-verified in the local content-addressed cache. The
disarmed projection is `batches/c-11-20-mega-width.toml`: 10 libraries × 37
qualified routes × 6 treatments = 2,220 exact executions.

This projection is intentionally not in `plans/priority-queue.toml`. At the
time it was added, all ten libraries reported `recipe-required`; a source pin
and a qualified toolchain do not constitute a build recipe.

The first authoring passes added fixed recipes for HarfBuzz, FreeType, Expat,
Brotli, libjpeg-turbo, libunistring, bzip2 1.0.8, libtiff, libpng and GLib.
Exact recipe pins match the C20 source authority and project detection was
checked against every cached source tree. This moves the read-only projection
to 10/10 recipe-ready and 2,220 materializable cells, but compilation
qualification is still outstanding and the batch remains disarmed.

The two dependency-bearing recipes require special care:

- GLib pins the upstream release's PCRE2, libffi, zlib and proxy-libintl
  source/WrapDB patch set. Its adapter writes the per-target cross file and
  forces those staged fallbacks; runtime network access is not acceptable.
- libpng uses the declarative secondary-input contract to pin zlib 1.3.1. Its
  adapter builds zlib with the same route and treatment inside each cell; do
  not replace that with a host or sysroot library.

The x86-64 Linux GLib configure canary resolved all four dependencies from the
staged offline cache. Run target-family/oldest-generation compilation canaries
for all ten before materialisation. Never mark the C11–C20 batch ready merely
to make it appear in the scheduler.

The repeatable authority for that gate is `qualification/c11-c20.toml` and the
command is `fidb-poc qualify-recipes qualification/c11-c20.toml`. It is a real
compilation command—never run it as a read-only status check. It uses four
workers, one O2 treatment and 16 target/generation edge routes (160 cells), and
does not invoke Ghidra. A stopped early diagnostic on 2026-09-05 retained four
failed HarfBuzz attempts in this checkout's ignored `qualification/evidence/`;
host PNG discovery was then disabled in the fixed adapter. Those attempts are
diagnostic evidence, not a completed qualification, and the authority has not
been rerun.

## C21–C30 staging

`coverage/c-top30-width-study.toml`, `sources/c-top30-v1.toml`, and
`batches/c-21-30-mega-width.toml` preserve ranks 21–30 as a disarmed 2,220-cell
projection. All ten primary archives are locally checksum-verified. The cache
is ignored local state, so another clone must use `source pull` or the reviewed
`source import` boundary; do not commit archive bytes.

Six recipes are authored but unit-tested only: zlib 1.3.2, libffi, libxml2,
libuv, OpenJPEG and Opus. libidn2, ICU, libgcrypt and GnuTLS are deliberately
recipe-blocked pending pinned dependency graphs or host-tool staging. The batch
must remain outside `plans/priority-queue.toml` until all ten recipes exist and
the same target-family/oldest-generation qualification is run and reviewed.
Never infer qualification from the projection's `materializable_executions`;
that field currently means only source/recipe/toolchain resolution.

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

Machine validation shares this retention engine but uses a bounded
`machine-validation` scope after a measured-complete run. The terminal report
and status must agree; every result, truth map, query-signature export and
composite binary is hashed before worker scratch becomes eligible. Only
TOML-selected direct-child `worker-*` directories may be removed. Never delete
`units/` or `reference-index.sqlite3`: the first C10 implementation reported a
five-signature library-level threshold rather than the requested exhaustive
hash-level confusion analysis, and the retained evidence is required to repair
that analysis without recompilation or another Ghidra run. Failed validation
runs are quarantined, not opportunistically cleaned.

The corrected exact-tuple survival diagnostic is `hash-report.json`, not the
older `report.json`. The latter accepted a whole library after five distinct
matches; that confused the operator's blocks-of-five design with a detection
threshold. Never resurrect that threshold. Run
`fidb-poc machine-validation analyze-hashes --run-id <sealed-full-run>` to
classify complete FID signatures against exact route/treatment references.
`hash-evidence.sqlite3` is the durable source for noisy-hash and low-information
analysis. TP/FP/FN observations are explicit; TN is reconstructed from
`unit_result.query_distinct_signatures * five withheld owners - FP`.

Do not report that diagnostic's FN rate as native FID recall. It compares raw
complete tuples and bypasses Ghidra's candidate scoring, relation weights,
force-specific rules, thresholds and winner selection. The canonical detector
validation is the separately versioned native-FID owner campaign governed by
`validation/fid-matching.toml` and `validation/fid-matching-run.toml`.

The first production dry-run selected 973 actions and 257,415,636,119 apparent
bytes but estimated 1,041.553 seconds, above the 600-second automatic ceiling.
It was therefore not applied. Do not raise that ceiling merely to clear the
backlog; review the exact plan and perform the initial collection manually if
the evidence set is acceptable.

## Machine-validation execution

The C10 machine-validation executor is independent of the production build
queue. Its TOML runtime is `validation/machine-validation-runtime.toml`; its
preflight must resolve all 2,220 exact signature inputs and must see the
production queue drained. Start a canary before a full run. A canary qualifies
the full run only when its report pins the current runtime digest, query-copy
policy and reference-index schema.

### Native-FID owner campaign

Use `machine-validation run-matcher`, not `analyze-hashes`, when the question is
whether Ghidra FID accepts the correct or an incorrect library owner. Its atomic
decision is one link-attributed query function against one of the ten candidate
owners. One function therefore contributes one positive decision and nine
negative decisions. Unresolved truth remains evidence but cannot enter the
confusion matrix.

The CPU and WGPU backends reproduce Ghidra `FidProgramSeeker`; they do not
invent a replacement similarity rule. Qualification requires exact owner
decisions and at most one float32 ULP of score drift. Ghidra remains the oracle.
The receipt `validation/evidence/portable-fid-c10-canary-v1.json` qualified both
backends on a retained case with zero decision mismatches. CPU was faster on
that small case because GPU dispatch dominated, so equivalence is not evidence
that WGPU will win every workload.

The scheduled campaign is `c10-native-fid-methodology-v1`. Its four-case canary
must cover both folds, reach 80% truth attribution and have zero oracle
mismatches before the full 444 cases can start. The full campaign uses four
workers with explicit JVM limits inherited from
`validation/machine-validation-runtime.toml`. It refuses active production
jobs, never executes target binaries, never starts a compiler and never mutates
the production queue.

Admission rechecks `minimum_available_memory_gib`, `minimum_free_disk_gib` and
the reviewed Ghidra headless executable from the runtime TOML before it creates
a campaign lock. Do not bypass this because a daytime observation looked safe;
the midnight resource state is the one that matters.

The timer is `fidb-fid-matching-campaign.timer`, at 00:00 Europe/Luxembourg.
It intentionally uses `Persistent=false`; otherwise enabling it during the day
could immediately run the missed midnight trigger. A case already admitted may
finish after 05:30. Check `campaign_status` and the four canary reports before
allowing automatic chaining; never hand-create a success receipt.

Each case retains native oracle input, portable outputs, truth attribution and
hash observations. Completion writes `full-hash-evidence.sqlite3` and a compact
report consumed by the validation observatory. Preserve both. Normal GUI reads
the compact report; drill-down reads bounded full/specific/complete populations
and affected owners. A future schema change gets a new sidecar, never an in-place
reinterpretation of this evidence.

Routine native-FID cases execute only the `selected` backend from
`validation/fid-matching.toml`—currently `cpu-portable-fid-v1`—and compare it
with the native oracle already required for the measurement. Do not restore
per-case CPU/WGPU dual execution. `qualify-matcher` is the explicit backend
equivalence operation and is the only normal reason to execute both paths.
The independent bulk exact-hash analyser continues to select WGPU through
`performance/hash-analysis.toml`; it also runs both paths only when explicitly
given `--qualify-backend`.

Do not simplify the v3 reference index back to a flat occurrence table. The
first compatibility-aware canary expanded repeated signatures across every
build occurrence: one Android fold remained in SQLite matching for more than
ten minutes and exceeded 4 GiB RSS. The v3 index retains exact-identity
presence plus one owner/signature row. The matcher uses `CROSS JOIN` to force
the small query table to be the outer loop; the same 18,526-function Android
query measured 0.075 seconds after that change. SQLite otherwise chose the
platform corpus as the outer loop and repeatedly scanned the query set.

The control panel polls `/api/v1/machine-validation/run`, not the full compiled
authority endpoint. Keep that lightweight runtime path: compiling the complete
2,220-input view measured roughly 2.2 seconds and is suitable for explicit or
periodic authority refresh, not a five-second progress poll.

Pause machine validation through its own control, not by restarting the API
service. The parent stops each worker process group (including Ghidra), retains
completed unit results and releases the runner lock. Resume keeps the same run
ID and skips completed units. A failed unit's concise `result.json` moves into
that unit's `attempts/` directory before retry, so repair does not erase the
original evidence. The runtime status also changes a missing or zombie parent
to `interrupted`; never trust a stored PID without checking its command and run
identity.

The first full C10 validation exposed a PowerPC/glibc harness edge in GCC 12 and
13 stack-protector routes: forced `-nostdlib` composite links cannot leave the
hidden `__stack_chk_fail_local` unresolved. The linker now retries only that
failure class with a target-compiler-built, zero-sized, never-executed ELF
function stub. Keep the stub outside `--whole-archive`, retain its source/object
beside the fold evidence, and replay the exact failed archive sets when changing
this behavior. Adding all of `libc_nonshared.a` is not equivalent: it pulled in
`atexit.oS` and failed on hidden `__dso_handle`.

The corrected hash analysis is separately admitted by
`validation/machine-validation-hash-schedule.toml`. Its 2026-09-05 afternoon
window is 13:45–18:15 Europe/Luxembourg and its recurring window is
00:00–05:30. Starting inside a window is the only clock gate; a started pass
finishes. It consumes retained JSONL and SQLite evidence and does not invoke
compilers or Ghidra. The checked-in user service and timers are named
`fidb-machine-validation-hash-analysis.service`,
`fidb-machine-validation-hash-analysis-afternoon.timer`, and
`fidb-machine-validation-hash-analysis-nightly.timer`.

C10 must also become generation one of the incremental corpus hash index before
its corrected report is published. The authority is
`validation/corpus-hash-index.toml`; the derived sidecar is
`artifacts/hash-discrimination/corpus-index-v1.sqlite3`. Do not add evolving
noise values to an immutable lane database and do not migrate a published lane
or validation database in place. A schema/authority change gets a new sidecar
path and a deterministic rebuild from retained evidence. Batch ingestion is
digest-idempotent and owners must be disjoint between cohort generations.

The C10 qualification established `gpu-wgpu-packed-probe-v1` for packed exact
lookup: zero mismatches over 3,025,703 queries and 3.31× the CPU packed-probe
throughput. The reviewed receipt is
`validation/evidence/c10-wgpu-packed-probe-v1.json`. Normal batches select the
backend through `performance/hash-analysis.toml`; `auto` uses WGPU when the
device/runtime and qualification are present and otherwise falls back to CPU.
Do not run both backends on every batch. Dual execution is an explicit
`--qualify-backend` operation after implementation or platform changes.

This backend never compiles, links, starts Ghidra, recovers functions or
generates FID hashes. It receives already-generated packed exact keys. Do not
describe the measured probe speedup as validation, Ghidra or build speedup.
Packed matrices are cached below ignored
`artifacts/hash-discrimination/packed-lookups/<generation-digest>/` and are
rebuildable from the corpus database.

Each newly materialised validation manifest must contain the required
`hash-discrimination` postprocess job and pin the method, corpus and backend
authorities. A full run is terminal only after report and retention complete.
`postprocess-failed` means the expensive build-analysis units are sealed:
recover from retained JSONL/SQLite evidence; do not start a fresh Ghidra run.

Do not interpret C10's 45.66% aggregate FN rate as intrinsic FID recall. Its
references are per-library archive functions but its queries are functions
recovered from five-library linked composites. The large architecture swing
(roughly 17% Linux x86-64 to roughly 90% MIPS32 BE) strongly implicates linker
and function-recovery construct effects. Future reports retain route,
treatment and owner FN strata. Preserve the raw observations and run a bounded
archive-to-executable control before accepting or rejecting the recall result.

The replacement validation harness is
`whole-archive-shared-image-symbolic-v2`. ELF composites are non-executed
shared images linked with `--whole-archive` and `-Bsymbolic`; the former
entry-zero executable and `--unresolved-symbols=ignore-all` combination is
forbidden. Every fold retains `link-audit.json`, and a direct call, jump or
branch to address zero fails the unit before Ghidra analysis. PE/COFF uses its
reviewed DLL link but passes the same post-link audit. Do not weaken this audit
to make a route green.

Ghidra imports shared images at an image base that need not equal linker-map
addresses. Native truth attribution therefore measures a symbol-supported
Ghidra-to-linker bias and records it in `oracle-input.json`; do not hard-code
the x86 observation of `0x100000` for another format or route. A bounded x86
control improved correct-owner full-hash candidate survival from 75.65% to
98.72% and native recall from 71.20% to 94.88% (2,370 TP, 128 FN, one FP,
22,481 TN). The repaired canonical canary also audited x86 ELF, Android
AArch64 ELF and Windows PE/COFF with zero direct-to-zero transfers.

`validation/fid-matching-run.toml` pins the required harness. Campaign status
reports its source-harness preflight, and campaign admission refuses a missing,
stale or failed fold. The old `20260904T152653Z-full` source is intentionally
blocked for native matching; never edit its retained result files to make them
appear current. The replacement source ID is
`c10-shared-image-symbolic-v2-full`. The GUI passes it to the bounded start API;
the equivalent CLI operation is `machine-validation start --mode full --run-id
c10-shared-image-symbolic-v2-full`. Run that source campaign under the current
manifest, then admit native matching against the same immutable run.
Use `scripts/trace_fid_misses.py --rebuild-composite --native-oracle` for
bounded investigations rather than launching the 444-case campaign while a
construction defect is unresolved.

The first corpus-admission attempt on 2026-09-05 exposed a scale-only SQLite
failure: `delta_rollup` joined every signature to an unindexed six-text-field
`delta_owner` table. SQLite chose `SCAN delta_owner LEFT-JOIN`; the attempt was
stopped after 5 h 43 m and about 60 TB of logical cached reads. The sealed
`hash-evidence.sqlite3` remained valid and the uncommitted partial index was
quarantined. The supported implementation now normalises query and owner rows
to `signature_id`, stores them in `WITHOUT ROWID` temporary tables with primary
keys, and joins the roll-up by that integer. Never remove
`test_delta_rollup_uses_signature_id_primary_key_lookup`; correctness-only tiny
fixtures did not reveal the original quadratic plan. After an interrupted
admission, stop the service, verify that no process owns the files, quarantine
the exact `.partial` plus journal, and clear or quarantine the stale
`.hash-analysis.lock` before retrying. Never remove the sealed source evidence.

Do not rerun the 41 GiB C10 composite/Ghidra workload to correct the old
five-match methodology. The sealed run already retains all 444
`query-signatures.jsonl` fold exports. `analyze-hashes` uses the lightweight
hash-analysis resolver: it verifies the 2,220 exact signature inputs and their
reference-index digest, but deliberately does not verify static archives,
inspect compiler executables, require a drained production queue, or launch a
JVM. Its `unit-local-reference-v1` engine loads one route/treatment's ten-owner
reference set once and reuses it for both folds; restoring per-fold scans of
the 3.3-million-row `reference_identity` table is a performance regression.
Keep observation writes bounded, retain the engine name and stage timings in
`hash-report.json`, and use a fresh canary only when changing the expensive
composite/Ghidra contract itself.

The classifier is cohort-generic. Do not restore the original `len(cohort) ==
10` acquisition gate: any frozen run must instead contain two non-empty,
duplicate-free, disjoint folds. The canonical method authority is
`validation/machine-validation-hash-method.toml`; its SHA-256 participates in
the source-evidence digest and is stored in the evidence database and report.
A formula, identity, denominator or safety change requires a new method ID,
not an in-place reinterpretation of historical rows.

Ghidra exposes a full hash and a specific hash, while exact FID matching here
uses both plus the additional-size and code-size fields. The evidence compiler
therefore materialises three views: full-only, specific-only and complete
tuple. Treat the first two as counterfactual ambiguity measurements. They do
not redefine TP/FP/TN/FN, and a component shared by several owners is not by
itself an actual false positive. Preserve the `hash_signature_owner`,
`hash_type_summary`, `hash_component_distribution`, `hash_component_noise`,
`hash_component_owner` and `hash_component_library` tables when extending the
analysis.

`src/fidb_poc/validation_observatory.py` and the read-only
`/api/v1/validation-observatory` endpoint are the bounded GUI projection.
Normal refresh reads compact JSON reports only; it must not open every large
evidence database. The all-runs response omits row-level lists, while one
selected immutable run carries its prevalence tail, ambiguous hashes, owners
and per-library burden. The Hash discrimination page deliberately puts that
measured output above future HDI fitting controls. Keep report, source-evidence
and method digests visible so a graph can always be traced to its authority.

# Source acquisition authority

The complete four-source N80 research frontier uses the staged source
acquisition process documented in `sources/README.md`. Do not write an ad-hoc
download loop or infer a source URL from a candidate name. Use `source
acquisition refresh`, inspect/freeze `resolve`, check `status`, and only then
run `pull`. The tracked lock is scientific input authority; the ignored
per-lock TOML acquisition registry is host evidence. A cached candidate is
still not screened, recipe-ready, qualified or admitted.

Do not remove the source-preference or URL-rewrite evidence from the lock.
Homebrew's Maven input is a binary distribution, while GNU/Savannah mirror
redirectors and Apache `closer.lua` are unreliable for generic acquisition
clients. The acquisition TOML selects Debian source for Maven and maps only
those known dynamic endpoints to stable direct archive endpoints. GNU payloads
use the kernel.org GNU mirror after both the redirector and GNU primary host
failed from `reference-host`; the registry SHA-256 remains authoritative. The lock
and receipt retain both URLs and the rewrite identity.

`opengl` is deliberately unresolved because it names a virtual API rather
than a unique source tree. Resolving it requires an explicit candidate-screen
decision about the implementation; silently substituting Mesa changes the
experimental population.
