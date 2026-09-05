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

Completed validation reports use one complete FID signature paired with one
library owner as the atomic assertion. There is no five-match or other
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

The earlier `report.json` remains immutable historical evidence of the
superseded five-signature library-level experiment. It is not an input to the
hash-discrimination ledger.

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

## Scheduled single-hash analysis

`machine-validation-hash-schedule.toml` admits the corrected analysis during a
one-off 13:45–17:00 Europe/Luxembourg window on 2026-09-05 and during the normal
00:00–05:30 nightly window. A started pass finishes after the admission window
closes. The scheduler selects only the latest sealed full run lacking a current
hash report; it never starts compilation or Ghidra and exits successfully when
nothing is pending:

```sh
uv run fidb-poc machine-validation scheduled-hashes --project-root .
```

The corrected pass reuses the 444 retained fold exports from the sealed full
run. Its `unit-local-reference-v1` engine verifies signature inputs without
rehashing retained static archives, loads the ten exact owner references once
per route/treatment, and reuses that bounded table for both folds. Match, miss
and unattributed observations are streamed to SQLite in bounded batches. The
terminal report records evidence-resolution, classification and total wall
time as well as zero compiler/JVM launches. A new composite build is neither
required nor desirable merely to replace the superseded five-match report.

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
