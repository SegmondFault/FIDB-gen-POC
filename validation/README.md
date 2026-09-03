# Machine validation

`machine-validation.toml` is the reviewed authority for continuous synthetic
validation of each completed ten-library cohort. It freezes a reproducible
random five/five split and defines a separate `validation-run` batch. This is
not ecological validation and it does not authorize automatic ablation.

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

Completed validation reports publish an explicit TP/FP/TN/FN decision matrix.
They also retain a row-level failure ledger for every false positive/collision
and false negative/miss, including the exact library, function, route, compiler,
treatment, signature, candidate owner and evidence locator. The GUI shows the
totals first and keeps this ledger expandable for diagnosis.

The first run rebuilds the reviewed recipes into two forced-inclusion static
composites for each exact width identity. It does not assume old per-library
archives were retained. Target programs are inspected and analysed but never
executed. The primary queries test the correct fold with the exact identity
withheld, the opposite fold, and the complete owner-labelled candidate index.
An exact-inclusion canary verifies the pipeline separately.

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
