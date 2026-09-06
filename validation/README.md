# Machine validation

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
uv run fidb-poc machine-validation start --project-root . --mode full
```

Active runs are checkpointed after every completed width identity. Pause stops
the worker process groups (including Ghidra children), preserves completed unit
results and releases the run lock. Resume keeps the same run ID, skips complete
units and retains each failed result under the unit's `attempts/` directory
before retrying it:

```sh
uv run fidb-poc machine-validation pause --project-root .
uv run fidb-poc machine-validation resume --project-root .
uv run fidb-poc machine-validation analyze-hashes --project-root . \
  --run-id 20260904T152653Z-full
```

The control panel exposes the same two bounded API operations. An active status
whose recorded parent process is absent is reported as `interrupted` and can be
resumed explicitly; PID reuse cannot make an unrelated process resumable.

The full run is rejected unless the latest successful canary records the exact
runtime-authority digest, query-copy policy and reference-index schema in use.
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
maps, query signatures and composite binaries. It may remove only direct-child
`worker-*` scratch directories.
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

`fid-matching-run.toml` schedules the C10 campaign. Four cases spanning both
folds and route classes form the fail-closed canary. Only a canary with at least
80% truth coverage and zero oracle mismatches chains into the 444-case full
run. Four long-lived campaign slots use the heap and processor bounds in
`machine-validation-runtime.toml`. No target executable is run, no compiler is
started, and the production queue is never mutated.

```sh
uv run fidb-poc machine-validation qualify-matcher --project-root . \
  --run-id 20260904T152653Z-full --position 1 --fold B
uv run fidb-poc machine-validation run-matcher --project-root . --mode canary
uv run fidb-poc machine-validation run-matcher --project-root . --mode full
uv run fidb-poc machine-validation scheduled-matcher --project-root .
```

Each case retains the native oracle input, CPU and WGPU decisions, comparison,
truth attribution and per-hash observations. A terminal campaign compacts those
observations into `full-hash-evidence.sqlite3`. The sidecar retains full,
specific and complete hash populations by compatible scope and owner, including
TP/FP/FN counts and shared, ambiguous and incorrect-confident attribution
categories. The full report is ingested by `/api/v1/validation-observatory`, so
the Hash discrimination page gains its population tail, noisy hashes and
library drill-down without opening all case evidence during normal refresh.

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
`corpus-hash-index.toml`. Later disjoint cohorts update only signature keys
present in their delta. Historical query counts and existing owner postings
account for newly possible cross-cohort matches; TN remains arithmetic. The
index is a rebuildable sidecar and neither lane databases nor immutable
per-run evidence are migrated.

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
