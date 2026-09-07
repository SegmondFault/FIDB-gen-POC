# Machine validation

## Integrated cohort lifecycle

`cohort-lifecycle.toml` is the reviewed policy joining future width builds to
machine validation, hash discrimination, retention and corpus admission. Its
atomic scientific unit is a completed library cohort, normally ten libraries.
The scheduler may divide that work into short, resumable execution blocks;
those blocks do not create new experiments or new fold assignments.

The five/five methodology is unchanged. For every exact route and treatment,
the runner builds one fold-A composite and one fold-B composite from the
committed seeded split. The primary TP/FP/TN/FN matrix remains the
present-fold-versus-withheld-fold experiment. A separate incremental query
compares the new cohort's signatures with the cumulative admitted corpus for
noise and discrimination analysis. Cross-corpus observations do not alter the
primary fold matrix.

New composite runs use `fidb-integrated-query-evidence/v1`. The single Ghidra
analysis writes one relationship-complete `query-signatures.jsonl` whose
sealed roles are `exact-signatures` and `fid-relationship-evidence`. The fold
result binds its schema, analysis policy, byte count and SHA-256. Routine
matching refuses an integrated result without that seal. Historical C10
results may use the explicit digest-bound one-time backfill route; future runs
may not silently pay for a second Ghidra analysis.

`cohorts.toml` binds the next concrete cohorts to their reviewed width batches.
It currently freezes C11–20 and C21–30, including exact releases, independent
seeds and derived five/five assignments. Both remain planned and disarmed until
their complete width evidence is sealed. The longer four-source C80 programme
inherits the lifecycle policy for every ten-library cohort and its explicit
final partial cohort, but cannot freeze exact subjects before candidate
screening.

The admission boundary is fail-closed. Source preparation and recipe
qualification may continue one cohort ahead. A validation failure pauses
admission of the next completed width cohort. Validation, hash-discrimination
and retention evidence are all required, and automatic corpus admission stays
disabled until scientific thresholds have their own reviewed authority.

The Matrix projects these authorities as separate Width, Validation and
Admission states. C10 appears as `legacy-run-retrofit`: its current old-path
execution is preserved and is not reinterpreted as a native integrated run.

The **Batch validation** view is the cohort ledger: select one scientific batch
to inspect its primary confusion matrix, failures, timing and immutable
evidence. Method, construction stages and frozen folds are collapsed beneath
that result. Cross-batch hash prevalence and cumulative noise trends belong on
**Hash discrimination**, rather than competing with the batch result.

`machine-validation.toml` is the reviewed authority for continuous synthetic
validation of each completed ten-library cohort. It freezes a reproducible
random five/five split and defines a separate `validation-run` batch. This is
not ecological validation and it does not authorize automatic ablation.

The sealed library cohort is the atomic validation and reporting boundary. A
cohort may execute across any number of scheduler windows without changing its
identity. Its library releases, exact-width digest, analysis policy, lane
generation, RNG seed, query contract and result evidence stay pinned together.
Later width changes create a new cohort revision rather than mutating a
published result. The control panel selects these validation batches directly;
completed attribution results lead the page, while processing, fold assignment
and provenance remain available in the expandable reproducibility section.

Inspect live admission status without changing the queue or filesystem:

```sh
uv run fidb-poc machine-validation status --project-root .
```

When, and only when, all ten families have complete evidence for every
applicable exact identity, materialise the disarmed validation manifest:

```sh
uv run fidb-poc machine-validation materialize --project-root . --write
```

The reconciler/materialiser refuses incomplete cohorts and never rewrites the
production `plans/priority-queue.toml`. It emits `kind = "validation-run"` work
under `plans/validation-materialized/` and automatically pins it in
`plans/validation-schedule.toml`. The first generated run stays claim-blocked
until a tiny post-cohort canary validates the composite executor; subsequent
validated cohorts may be admitted automatically by the normal scheduler.

The 222 exact identities are a recorded starting baseline, not a ceiling. Live
eligibility is compiled from every applicable execution identity in the width
authority. Adding a route, compiler version or treatment therefore increases
the requirement automatically and returns the cohort to an incomplete state
until that new evidence exists.

Normal cohorts are exactly ten. If the final library total leaves a remainder,
set `cohort_policy.final_partial_override = true` in a new final-cohort TOML,
record a non-empty justification, and list 2--9 pinned libraries. The same
seeded ranking makes a balanced split; an odd final cohort differs by one
library between folds. This exception is explicit and visible in the GUI.

The retained exact-tuple diagnostic uses one complete FID signature paired with
one library owner as its atomic assertion. There is no five-match or other
library-acceptance threshold. For each exact route and treatment, signatures
from the five libraries present in the composite define the positive
population; query signatures checked against the five withheld libraries define
the negative population:

- TP: an expected exact signature is present in the composite query;
- FN: an expected exact signature is absent from the composite query;
- FP: a query signature also exists under an opposite-fold library owner;
- TN: a query signature does not exist under an opposite-fold owner.

Sharing among libraries in the same composite fold is retained as multi-owner
ambiguity and is not called false. The canonical `hash-report.json` gives the
matrix and bounded leading rows. `hash-evidence.sqlite3` retains every TP, FP
and FN observation by route, treatment, fold, owner and complete signature;
TN is exactly reproducible from each fold's query-signature count and withheld
owner count. This avoids materialising millions of negative non-matches without
changing the denominator.

This comparison measures exact signature survival and sharing. It does not
model Ghidra's candidate scoring, relation weights, force-specific rules or
winner selection and therefore is not a native FID recall measurement. The
earlier `report.json` remains immutable historical evidence of the superseded
five-signature library-level experiment. Neither report is an input to the
native-FID confusion matrix.

FN is a harness-conditional observation. The positive reference unit is a
function recovered from one library archive; the query unit is a function
recovered after five archives have been linked into one composite. Linker
symbol selection, weak/COMDAT coalescing, relaxation, thunks/veneers and Ghidra
boundary recovery can change that population. The aggregate FN rate is
therefore not an intrinsic FID-recall estimate. New reports retain FN/TP by
route, treatment and library and show the route-rate spread. C10 remains
construct-validity evidence under investigation until a bounded
archive-to-executable control isolates those transformations.

The first run rebuilds the reviewed recipes into two forced-inclusion static
composites for each exact width identity. It does not assume old per-library
archives were retained. Target programs are inspected and analysed but never
executed. The canonical classifier compares the composite with the same exact
route/treatment signature sets for present and opposite-fold owners. The
canary qualifies archive reconstruction, composite linking, object formats,
Ghidra extraction and reference-index compatibility separately.

Execution settings live in `machine-validation-runtime.toml`. Preflight checks
all 2,220 signature inputs, the 2,046 retained archives, the 174 reconstructable
OpenSSL archives, the drained production ledger, free disk and available RAM:

```sh
uv run fidb-poc machine-validation preflight --project-root .
uv run fidb-poc machine-validation start --project-root . --mode canary
uv run fidb-poc machine-validation start --project-root . --mode full \
  --run-id c10-shared-image-symbolic-v2-full
```

Every new source-validation run also requires the all-width link qualification
defined by `machine-validation-link-qualification.toml`. This is a separate,
disarmed pre-Ghidra stage: it resolves each exact route and treatment, links and
audits both folds, and creates the stripped query image for all 444 fold cells.
It does not import a program into Ghidra and never executes a target binary.

```sh
# Compile and inspect the exact 444-cell qualification plan.
uv run fidb-poc machine-validation qualify-links --project-root .

# Run it explicitly; the command stops after four identical failures.
uv run fidb-poc machine-validation qualify-links --project-root . --execute

# Verify the sealed receipt and every retained truth/query digest.
uv run fidb-poc machine-validation qualify-links --project-root . --status
```

The input digest binds the validation authority, fold assignment, exact width,
toolchain and recipe authorities, archive population, link/query policies and
implementation. Evidence lives below the digest-named directory in
`qualification/evidence/machine-validation-links/`. A successful seal is
therefore reusable only for precisely the inputs it qualified. New runs
hardlink those prepared images when possible and fall back to a byte-for-byte
copy; partial run-local folds are preserved rather than overwritten.

The circuit breaker schedules at most four new fold cells at once. Four
matching normalized failure fingerprints open it, retain the individual error
and partial link evidence, and leave the rest untouched. Fix the cause and run
the same command again; successful cells are not repeated and failed evidence
is not cleared. The existing checkpoint
`c10-shared-image-symbolic-v2-full` is the sole explicit grandfathered run,
because changing its already-pinned preparation authority would discard valid
completed work. This exception permits only resume of that exact run ID.

Active runs checkpoint each fold as well as every completed width identity.
Pause stops the worker process groups (including Ghidra children), preserves
completed results and releases the run lock. Resume keeps the same run ID and
skips complete units and folds. Failed cells are terminal until an operator
names them with the evidence-preserving requeue command; the command moves each
failure under the unit's `attempts/` directory and writes a requeue receipt:

```sh
uv run fidb-poc machine-validation pause --project-root .
uv run fidb-poc machine-validation requeue-failed --project-root . \
  --positions 19,22,23
uv run fidb-poc machine-validation resume --project-root .
uv run fidb-poc machine-validation analyze-hashes --project-root . \
  --run-id 20260904T152653Z-full
```

Interactive resume detaches after it has started the runner. Service chains use
`machine-validation resume --foreground` instead: the command remains attached
until source analysis, hash post-processing and retention finish, and returns a
non-zero status unless the run reaches `measured-complete`. This prevents the
native-FID canary from racing an incomplete source run.

The control panel exposes the same two bounded API operations. An active status
whose recorded parent process is absent is reported as `interrupted` and can be
resumed explicitly; PID reuse cannot make an unrelated process resumable.

Before Ghidra starts, the runner prepares linked and stripped fold images in
bounded batches using the TOML `preparation_workers` and
`preparation_batch_size`. Atomic `prepared.json` files bind those images to the
runtime, route, treatment, fold and harness. Long-lived Ghidra workers then
draw cells from one filesystem-atomic claim queue in longest-observed-route
order; an idle worker can take work that would previously have been stranded
behind a slow static shard.

Each worker writes its current cell and start time below the run's `workers/`
directory. The parent supervisor applies the TOML `cell_timeout_seconds`, stops
the complete worker process group when a cell exceeds it, releases its exact
claim and starts a fresh JVM. A timed-out cell receives the reason code
`cell-timeout`; it is retried only up to `cell_timeout_attempts`. Unexpected
worker exits also release their claims and are bounded by
`maximum_worker_restarts`. Ordinary cell failures remain visible but do not
abandon unrelated work. These settings are operational safety bounds, not
permission to weaken a failed link audit or discard its evidence.

An explicit operator requeue is also an explicit retry-generation boundary.
Attempts archived before the latest immutable requeue receipt remain evidence,
but do not consume the new generation's automatic timeout allowance. This is
not an unlimited retry mechanism: each reviewed requeue is named, stopped-run
only, position-bounded and receipt-backed.

Ghidra 12.1.2 can fail to converge while repairing overlapping SuperH function
bodies. A live JVM thread dump traced the observed loop through `Call-Fixup
Installer`; `Non-Returning Functions - Discovered` contains a second
unconditional route into the same repair command. A first timeout remains the
normal, unaltered Ghidra analysis attempt. A subsequent attempt for that same
SuperH unit selects the named
`superh-clear-flow-repair-analyzers-disabled-after-timeout-v1` recovery policy,
which disables those two analyzers only. Every recovered fold and the aggregate
report record the policy; other architectures and SuperH cells without a
retained timeout continue to use `ghidra-default-auto-analysis-v1`.

The full run is rejected unless the latest successful canary records the exact
scientific canary-contract digest, query-copy policy and reference-index schema
in use. Worker counts, polling, retries and timeout bounds remain visible in the
runtime authority but do not change that digest or invalidate a successful
harness canary.
The reference index stores exact identity presence separately from one
owner/signature row. Query lookup is deliberately query-first against that
primary key; reversing the join order recreates a many-occurrence intermediate
and is a measured performance regression. Run the canary after changing either
the schema or the matching query.

## Post-run retention

After a canary or full run reaches `measured-complete`, the runner calls the
shared retention collector using the `machine-validation-complete` trigger.
The TOML authority is `retention/policy.toml`. It always creates a
content-addressed dry-run first and applies only when the estimate is within the
reviewed bound.

Validation retention verifies the status/report completion contract, the
single-hash evidence database digest, and the preserved unit results, truth
maps and query signatures. Once relationship-complete truth is sealed, the
source runner prunes disposable composite binaries. The native-FID campaign
separately removes only its reviewed scratch allow-list: `worker-scratch/`,
legacy `compact-index-ghidra-user/` and `cases/*/work`. It never infers cleanup
targets from a glob outside the campaign root.
Incomplete and failed runs remain quarantined whole. `units/`, the cohort
reference index and terminal reports remain available for threshold-free
per-hash reanalysis.

## Native FID owner validation

`fid-matching.toml` freezes a portable implementation of Ghidra
`FidProgramSeeker` candidate lookup, float32 scoring, relation handling,
thresholding and equal-winner selection. The native Ghidra implementation is
the oracle. Both the CPU and WGPU implementations must reproduce every oracle
owner decision and remain within one float32 ULP for each score.

The decision unit is one **query function × candidate library owner**. Linker
map attribution supplies the expected owner; an unambiguous reference name is
the bounded fallback. Unresolved functions are retained but excluded from TP,
FP, TN and FN. For every labelled query function, the expected owner contributes
one TP or FN decision and each of the other nine C10 owners contributes one FP
or TN decision. This directly measures the detector users will run; it does not
infer detection from raw tuple equality.

The qualification receipt in
`evidence/portable-fid-c10-canary-v1.json` records zero decision mismatches for
CPU and hardware WGPU against the native oracle. Its one retained x86-64/GCC 12
case is an implementation qualification, not the C10 result. At that small
scale CPU completed the portable scoring faster because GPU dispatch dominated.
Backend selection therefore remains measured and configurable rather than
assuming that a qualified GPU is always faster.

`fid-matching-run.toml` schedules the C10 campaign. One reusable compact SQLite
index holds the relationship-complete candidate population; routine cases
stream their sealed query signatures through the selected CPU or WGPU scorer.
Native Ghidra is replayed only for the four fail-closed canary cases spanning
both folds and route classes. Only a canary with at least 80% truth coverage,
zero oracle mismatches, the requested backend and zero fallback chains into the
444-case full run. Four campaign slots use the bounds in
`machine-validation-runtime.toml`. No target executable is run, no compiler is
started, and the production queue is never mutated.

The execution TOML selects `largest-query-first-greedy-v1`. Before workers are
started, completed cases are reused only when their source run, matching
authority, position, fold and link-harness policy still agree. Remaining cases
are weighted by the sealed query's `functions_hashed`, ordered largest first
and greedily assigned to the lightest worker. This prevents periodic folds and
treatments—especially the OpenSSL/O0 combination—from concentrating on a
single worker while preserving deterministic, inspectable scheduling.

```sh
uv run fidb-poc machine-validation qualify-matcher --project-root . \
  --run-id 20260904T152653Z-full --position 1 --fold B
uv run fidb-poc machine-validation run-matcher --project-root . --mode canary
uv run fidb-poc machine-validation run-matcher --project-root . --mode full
uv run fidb-poc machine-validation scheduled-matcher --project-root .
```

The backend and bounded dispatch settings live in
`performance/fid-matching.toml`. The Performance page exposes the requested,
effective and qualified FID scorer independently of the exact-hash analyser.
The canary retains its replay input, selected-backend decision and oracle
comparison. Routine full cases retain classifications, truth attribution,
per-hash observations and summary receipts, but neither native-oracle input nor
the large raw backend decision stream. CPU/WGPU dual execution is reserved for
the explicit `qualify-matcher` operation; the checked-in qualification receipt
is reused by normal campaigns.
A terminal campaign compacts those
observations into `full-hash-evidence.sqlite3`. The sidecar retains full,
specific and complete hash populations by compatible scope and owner, including
TP/FP/FN counts and shared, ambiguous and incorrect-confident attribution
categories. The full report is ingested by `/api/v1/validation-observatory`, so
the Hash discrimination page gains its population tail, noisy hashes and
library drill-down without opening all case evidence during normal refresh.

Campaign exclusivity uses an advisory lock with an inspectable PID/timestamp
record. The kernel releases ownership if the coordinator is stopped or
crashes, so the same campaign can resume its sealed cases without manually
deleting a stale sentinel. Replaying the surrounding systemd chain is also
safe: a complete source-validation stage is an evidence-checked idempotent
success, while missing terminal hash or retention evidence still blocks.

An unsealed matcher case may retain `failure.json`. Before that exact case is
retried, the worker moves the prior record to
`attempts/attempt-NNN-failure.json`; it never overwrites or discards the earlier
failure. A later sealed `summary.json` is authoritative for aggregation, while
the ordered attempt records preserve why previous executions stopped.

The user timer starts admission at 00:00 Europe/Luxembourg. `Persistent=false`
is intentional: installing or enabling it after midnight must not immediately
launch a missed heavy run. Work admitted inside the 00:00–05:30 window is
allowed to finish. Admission also rechecks the runtime TOML's available-memory
and free-disk floors and the reviewed Ghidra executable before creating a run
lock.

### Archive-to-executable miss trace

Do not assume that a native-FID scorer can recover a function if the synthetic
link has already changed its full hash. Trace selected functions through the
retained archive member, a one-library executable and the original five-library
composite with:

```sh
uv run python scripts/trace_fid_misses.py \
  --run-id 20260904T152653Z-full --position 1 --fold B \
  --function 'gettext@1.0:_libintl_find_domain' \
  --rebuild-composite --native-oracle \
  --output qualification/evidence/fid-fn-trace
```

The bounded 2026-09-06 x86-64/GCC 12 trace sampled eight old TP/FN functions
from gettext, SQLite, GMP and PCRE2. All eight retained the same ELF symbol size
and machine-instruction count from archive member through both linked forms, so
the linker had not removed those functions. Only five of eight reference full
hashes survived the one-library link, and only four survived the five-library
link.

The failures exposed more than one boundary effect. `_libintl_find_domain`
remained a 734-byte, 204-instruction symbol, but unresolved calls resolved to
address zero and Ghidra recovered only 14 code units instead of the archive
reference's 177. Two GMP functions kept their complete machine-code extent but
changed full hash during relocation relaxation or address resolution.
`sqlite3PcacheTruncate` preserved its archive full hash in the one-library
control, then changed in the five-library composite while its 198-byte,
62-instruction extent remained intact. These are harness-induced candidate
losses before FID scoring, not evidence that the score threshold rejected the
correct library.

The portable matcher correctly reproduces the native decision for the
signatures it is given; it cannot rescue a correct reference candidate that is
absent from the full-hash bucket.

### Repaired shared-image harness

The current harness links ELF composites as non-executed shared images with
`--whole-archive` and `-Bsymbolic`. It no longer creates an entry-zero
executable or permits unresolved symbols to become direct calls to address
zero. Every linked ELF or PE/COFF image is disassembled before Ghidra analysis;
the unit fails if the audit finds a direct call, jump or branch to zero. Native
truth attribution measures and records Ghidra's image-base bias against the
retained symbol table before applying linker-map intervals.

Some GMP ARM32 and i686 Android archives contain non-PIC assembly and cannot be
placed in a strict shared image. The linker now retries only the recognised
Android 32-bit `R_ARM_ABS32`/`R_386_32` failure with `-z notext`. The audit
records `linker_compatibility = "android-32-text-relocations"` and
`text_relocations_permitted = true`; the same zero-target control-flow audit
remains mandatory. Other targets and other link failures remain strict. This
is a validation-image accommodation, not permission to relabel or rebuild the
sealed production archives.

On the same x86-64/GCC 12 fold used by the bounded diagnostic, correct-owner
full-hash candidate survival increased from 1,886/2,493 (75.65%) to
2,466/2,498 (98.72%). The native Ghidra owner oracle then measured 2,370 TP,
128 FN, one FP and 22,481 TN: 94.88% recall, 99.96% specificity and 99.96%
precision. All eight originally selected trace functions retained their
reference full hash in both the repaired one-library and five-library links.

The canonical repaired-harness canary completed four folds covering x86-64
ELF, AArch64 Android ELF and x86-64 PE/COFF with zero audited transfers to
address zero. A native-FID campaign now refuses any source fold that lacks the
current harness identity or its successful link audit. Historical C10 source
evidence remains immutable and cannot be reused for the replacement campaign;
produce a new full validation source run first.

The replacement source ID is pinned in `fid-matching-run.toml` as
`c10-shared-image-symbolic-v2-full`. The control panel passes that exact ID when
starting the next full validation, and the API/CLI reject path-unsafe or reused
IDs. Once the source run seals, the native-FID scheduler consumes that same
immutable run without a manual TOML rewrite. Canary runs retain timestamped IDs
because they are gates rather than campaign evidence.

The remaining x86 miss population is real under this controlled construction,
but not yet ecological recall. Of 2,498 labelled query functions, 32 have no
correct-owner full-hash candidate and 96 have a correct candidate but are not
accepted as the correct owner. Preserve those populations separately when
tuning candidate coverage, relationship scoring or size thresholds.

## Legacy exact-tuple analysis

`machine-validation-hash-schedule.toml` admits the exact-tuple diagnostic during a
one-off 13:45–18:15 Europe/Luxembourg window on 2026-09-05 and during the normal
00:00–05:30 nightly window. A started pass finishes after the admission window
closes. The scheduler selects only the latest sealed full run lacking a current
hash report; it never starts compilation or Ghidra and exits successfully when
nothing is pending:

```sh
uv run fidb-poc machine-validation scheduled-hashes --project-root .
```

The diagnostic pass reuses the 444 retained fold exports from the sealed full
run. Its `unit-local-reference-v1` engine verifies signature inputs without
rehashing retained static archives, loads the ten exact owner references once
per route/treatment, and reuses that bounded table for both folds. Match, miss
and unattributed observations are streamed to SQLite in bounded batches. The
terminal report records evidence-resolution, classification and total wall
time as well as zero compiler/JVM launches. A new composite build is neither
required nor desirable merely to replace the superseded five-match report.

Before publishing the C10 report, the pass transactionally admits its sealed
hash evidence as generation one of the cumulative index governed by
`corpus-hash-index-v2.toml`. Later disjoint cohorts update only signature keys
present in their delta. Historical query counts and existing owner postings
account for newly possible cross-cohort matches; TN remains arithmetic. The
index is a rebuildable sidecar and neither lane databases nor immutable per-run
evidence are migrated.

`corpus-hash-index.toml` and `corpus-index-v1.sqlite3` remain the immutable
historical authority and sidecar cited by the original materialized job. The
current v2 authority publishes `corpus-index-v2.sqlite3`; v1 is not mutated or
mixed with current-method observations. The current C10 run is allowed across
that boundary only by the exact paths and SHA-256 digests in
`postprocess-authority-transitions.toml`, and its report preserves that receipt.
Future batches cite v2 directly. An evidence batch whose method ID or digest
differs from the first admitted batch fails before source hashing and delta
staging and requires a new sidecar authority/path.

A downstream hash-analysis or corpus-admission failure does not manufacture a
failed source cell. `postprocess-failed` is resumable only when the filesystem
still proves that every expected full-run cell is complete and none is failed;
resume then reruns aggregation/post-processing from those sealed results. This
also repairs status written by older runners that reported the downstream
failure as one failed work unit.

`hash-analysis-backends.toml` records qualified exact-lookup backends and
`../performance/hash-analysis.toml` selects `auto`, `gpu` or `cpu`. C10
qualification returned zero mismatches over 3,025,703 queries and measured a
3.31× packed-probe speedup. Normal validation executes the WGPU packed exact
lookup once when available and falls back to CPU on absence or failure.
Packing is cached by corpus-generation digest. CPU/GPU comparison runs only
with the explicit `analyze-hashes --qualify-backend` operation.

That acceleration boundary is deliberately narrow. It does not compile code,
invoke a linker, recover functions, run Ghidra or generate FID hashes; changing
those stages could change scientific evidence rather than merely how
already-generated exact keys are looked up.

Corpus delta staging must resolve complete identities to `signature_id` once
and use the indexed integer-key roll-up. The regression suite rejects SQLite's
quadratic `SCAN delta_owner LEFT-JOIN` plan, which is not visible in tiny
correctness fixtures.

`machine-validation-hash-method.toml` is the versioned scientific authority.
It removes cohort-size assumptions from the analyser, defines the compatible
scope and complete FID identity, fixes the absence of a library-level match
threshold, and pins the full/specific/complete component comparison. Its digest
is included in both the evidence database metadata and terminal report; a
method change therefore invalidates cache reuse and creates new evidence.

The evidence database also stores `hash_type_summary`,
`hash_component_distribution`, `hash_component_noise`,
`hash_component_owner` and `hash_component_library`. Full-only and
specific-only rows measure component ambiguity; the complete tuple remains the
classification identity for TP/FP/TN/FN. The local read-only endpoint
`/api/v1/validation-observatory` lists compact summaries for every measured
run. Supplying one `run_id=<validation-id>:<run-id>` adds the bounded per-run
distribution, hash/owner and library drill-down without loading every SQLite
database into the control panel.

The systemd service and two timers in `operations/` call that command. A
successful scheduled pass immediately invokes validation-scoped retention, so
worker build/Ghidra scratch is considered only after the hash database and its
digest are durable.

Formal ecological validation comes later, after the intended dataset and lane
generation are frozen. It uses held-out real binaries in tag-only/shadow mode
and is the release gate for operational boilerplate ablation.

## Ecological validation

`ecological-validation.toml` is the separate held-out real-binary authority.
The control panel and CLI can import ELF, PE/COFF and thin Mach-O files into a
bounded project-local case store. Imported bytes are preserved, SHA-256 pinned
and never executed. Format, target, lane, Ghidra language and compiler-spec
routing are derived before a check is admitted. Ambiguous ELF platform cases
can be given an explicit Linux or Android hint; universal Mach-O files must be
split into thin slices so each analysis has one unambiguous sublane.

Each check queries the latest compatible lane generation across its complete
library-owner population. Incompatible architecture/OS lanes are deliberately
excluded: they are not query-compatible and cannot contribute a meaningful
negative. The matching engine compares the full FID identity tuple, preserves
all owner occurrences and records the exact corpus generation digest.

Ecological TP/FP/TN/FN uses an **imported binary × corpus library presence**
decision. Supply expected-present and expected-absent `family@version` labels.
If the ground-truth-complete flag is set, every unlisted corpus owner is an
expected negative. If labels are incomplete, unknown owners remain unlabelled
rather than being silently counted as false positives. Unlabelled files can be
run as exploratory checks, but their confusion counts remain blank.

Every unexpected match retains target address/function, corpus function,
signature, route, compiler, treatment and database evidence. Every expected
library with no match produces a specific miss row. The first usable run stays
blocked until a compatible lane database exists; importing a file cannot
create, compact or admit a corpus generation.

## Noisy-hash trust ledger

`noisy-hashes.toml` turns collision reports from both validation processes into
one reviewable trust ledger. Its identity is not a bare numeric hash: records
are grouped by query-compatible sublane plus the complete FID signature tuple.
This prevents equal values from incompatible targets being treated as the same
failure mode.

One collision creates a visible candidate. The checked-in starting threshold
marks a signature confirmed noisy only after at least three collision rows in
at least two independent reports. A signature affecting two or more owners is
also marked high risk. These thresholds are classification aids, not automatic
proof that the signature is unusable: common source, compiler boilerplate and
genuinely shared functions can all be repeatedly ambiguous.

Inspect the current ledger without changing evidence:

```sh
uv run fidb-poc noisy-hashes status --project-root .
```

Management decisions are individual TOML files under
`validation/noisy-hash-decisions/`. The GUI and CLI permit `observe`,
`quarantine`, `reviewed-shared` and `cleared`, require a written reason, and
pin the source status digest. Quarantine is a contract for excluding the
signature from a **future** admission generation; it never edits or deletes a
published raw or compact database. That downstream admission filter must be
implemented and verified before quarantine is treated as operationally
enforced.

The complete population remains in the evidence databases. The API returns
the ranked working set bounded by `display.max_hash_rows` in
`noisy-hashes.toml`, alongside exact `observed_hashes`, `returned_hashes` and
`hash_rows_truncated` counts. The authority catalog embeds only the complete
summary and population digest. This keeps browser refreshes below the fixed
transport limit without presenting a truncated list as the whole ledger.

## Hash Discrimination Index

The noisy-hash ledger is one input to the broader Hash Discrimination system.
That system will estimate the provenance value of every compatible FID
signature, not merely collect signatures which already appeared in collision
reports. Its principal analyst-facing measure is the **Hash Discrimination
Index (HDI)**: higher means more useful for distinguishing a library. A
separate noise-risk measure records ambiguity or demonstrated attribution harm,
and every result retains evidence sufficiency and an explainable reason.

Until the first complete C10 corpus and validation evidence exist, the
authority and GUI are readiness projections only. They must not invent scores
or enable filtering. The full measurement, generation, treatment-ablation and
rollback contract is documented in
[`../HASH_DISCRIMINATION.md`](../HASH_DISCRIMINATION.md).

Inspect the current formula, component weights, source readiness and immutable
generation plan without changing any evidence:

```sh
uv run fidb-poc hash-discrimination status --project-root .
```

The same authority is projected on the **Hash discrimination** control-panel
page. Its formula and reproducibility panels are generated from TOML rather
than duplicated as frontend constants.
