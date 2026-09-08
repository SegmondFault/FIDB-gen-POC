# Hash discrimination

FID hash equality is evidence that two analysed functions are indistinguishable
under the selected FID policy. It is not, by itself, evidence that one library
is the unique source of the function. Common ancestry, vendored source,
compiler/runtime scaffolding, trivial functions and genuinely ambiguous FID
signatures can all produce real matches which have weak provenance value.

The Hash Discrimination system is intended to learn how useful each compatible
FID signature is for distinguishing library provenance. It is not a destructive
"noisy hash filter". Its primary output is a **Hash Discrimination Index
(HDI)**, accompanied by a separate noise-risk estimate, evidence sufficiency
and an explainable reason classification.

## Analyst-facing measures

HDI is displayed on a 0--100 scale. Higher values mean the observed signature
has greater discriminative value for the stated owner and query-compatible
sublane. HDI is not initially a probability. A published generation must state
the exact formula or calibrated model which produced it.

Noise risk is also displayed on a 0--100 scale, with higher values indicating
greater observed ambiguity or attribution harm. It is not defined as
`100 - HDI`: an under-observed signature and a repeatedly misleading signature
can both have weak discriminative support while requiring different treatment.

Every score must also retain:

- the compatible query sublane and complete FID signature identity;
- the candidate library or resolution level to which the value applies;
- the corpus and model generation;
- component measurements and sample counts;
- evidence sufficiency or uncertainty;
- an observed or inferred reason, with its provenance and confidence; and
- any manual disposition, without rewriting the measured result.

The GUI may use the familiar word "hash", but the implementation identity is
the query-compatible sublane plus the complete FID signature tuple. Equal
numeric values from incompatible sublanes are not pooled.

## Initial signals

The first inspectable model should preserve components rather than hide them
behind one opaque number:

1. prevalence across distinct library families;
2. owner concentration or entropy;
3. prevalence across releases, lanes, targets, architectures, compiler
   families, versions and treatments;
4. participation in shared, ambiguous or incorrect library-level decisions;
5. function size and triviality where available;
6. relational corroboration where retained by FID analysis; and
7. score stability and drift as the corpus grows.

Raw build occurrences are not independent observations. The prevalence
denominator must count library families before releases, compiler variants and
treatments so that a library with greater build width does not appear
artificially common.

## Hash representations and the validation observatory

The controlled machine experiment uses the complete FID signature tuple for
ground-truth decisions: Ghidra language, full hash, specific hash, specific
additional size and code-unit size inside a compatible target/format scope.
The full and specific hashes are also analysed separately as counterfactual
components. The complete signature is not a third independent hash algorithm;
it is the matching identity assembled from both hashes and the size fields.

For each run, `hash-evidence.sqlite3` retains the owner population behind all
three representations. It records distinct values, singleton and multi-owner
values, owner links, prevalence by number of distinct owners, affected
libraries and exact-signature false-positive participation. It also counts the
component/owner cases that are ambiguous under full-only or specific-only
identity but unique under the complete tuple. This shows which representation
loses discrimination without mislabelling a component collision as an actual
FID false positive.

The primary prevalence denominator is distinct library-release owners within
the compatible scope. Reference-observation counts remain available as a
width-sensitive diagnostic, not as independent-library evidence. Exact
TP/FP/TN/FN rates continue to use the complete tuple; full-only and
specific-only prevalence answer how much ambiguity each component would create.

The read-only validation observatory indexes every measured `hash-report.json`
without scanning its large evidence database during a normal GUI refresh. Its
all-runs view preserves batch identity, method/report/source digests and trend
points. Selecting a run loads its bounded distribution, per-library table and
top ambiguous values with owner provenance. Historical reports are never
rewritten, so later C20/C30 and cross-language views can show population drift
and be reproduced from the pinned run databases.

Observed facts and inferred explanations remain separate. Initial reason
categories are compiler/runtime boilerplate, widespread cross-library reuse,
library-family or common-ancestry reuse, cross-language reuse, trivial/small
function, empirically misleading attribution, unexplained ambiguity and
insufficient evidence. Unknown is the safe default.

## Provisional transparent calculation

The checked-in C10 authority specifies an inspectable starting formula. Every
component is normalised to `[0, 1]`; the weighted sum therefore produces a
`[0, 100]` index:

```text
HDI = 35r + 25c + 20v + 10s + 10t
noise risk = 35a + 35i + 20(1-r) + 10(1-t)
```

Where:

- `r` is library-family rarity:
  `ln((N + alpha) / (df + alpha)) / ln((N + alpha) / (1 + alpha))`;
- `N` is the distinct compatible corpus library-family count and `df` is the
  number of those families containing the signature;
- `c` is one minus normalised owner entropy;
- `v` is one minus the beta-smoothed ambiguous-or-incorrect validation rate;
- `s` is supporting applicable build identities divided by all applicable
  build identities for the candidate owner;
- `t` is `clamp((median_code_units - 4) / (24 - 4), 0, 1)`;
- `a` is the beta-smoothed ambiguous-attribution rate; and
- `i` is the beta-smoothed incorrect-confident-attribution rate.

The starting beta prior is `alpha = 1`, `beta = 1`. These weights and
transforms are hypotheses to ablate, not established truth. They are visible in
the GUI and remain inactive until the evidence contract is satisfied. A change
to any component, weight, smoothing value or rounding rule requires a new model
version and a replay against the same unweighted baseline.

## Reproducibility

Score compilation is deterministic. Rows are ordered by compatible sublane,
complete signature and candidate owner; the initial model uses no random input,
IEEE-754 binary64 arithmetic and six-decimal rounding. Every immutable model
generation must retain:

- the algorithm and model version;
- the TOML authority digest and source-code Git revision;
- lane corpus generation IDs and content digests;
- machine/ecological report and manual-decision digests;
- component parameters, weights, smoothing and rounding rules;
- the ordered input population and all component outputs; and
- the generated-at timestamp and output digest.

Generation publication is create-only. Re-running the same pinned inputs must
produce the same score rows and digest; it must never overwrite an existing
generation. This provides the audit and rollback boundary for every later
matching-policy experiment.

## Attribution and treatments

The detector ultimately aggregates a set of distinct signature contributions
for each candidate owner. Repeated occurrences of one signature are capped. A
weak hash can support a coherent group of distinctive hashes but must not carry
a confident provenance claim alone.

Library-level results distinguish:

- unique library evidence;
- family-level or shared-code evidence;
- ambiguous attribution;
- insufficient evidence and abstention; and
- incorrect confident attribution when ground truth is available.

Every frozen validation corpus is replayed against at least four policies:

1. the unweighted FID baseline;
2. exclusion of a narrowly defined harmful population;
3. HDI-based down-weighting; and
4. retention as context-only evidence requiring independent corroboration.

No treatment is enabled for production matching merely because the score
compiler exists. Exclusion never deletes raw observations or historical lane
generations.

## Generations and validation boundary

Model snapshots are immutable and named for their evidence boundary, for
example `hash-discrimination-c10-v1`, `hash-discrimination-c20-v1` and
`hash-discrimination-c30-v1`. Detection reports pin the exact model generation.
Recalculation creates a new generation; it never edits an old score in place.

C10 has too few independent library families for a flexible learned model.
The first generation therefore uses an explicit, inspectable formula with
smoothed rates and visible uncertainty. Compiler and treatment variants measure
stability, but do not count as independent libraries. More flexible calibration
requires later cohorts and forward evaluation: learn from one frozen corpus
generation and test against the next additions.

Machine validation supplies ongoing controlled evidence. The ecological corpus
remains the held-out release gate and must not be used both to tune a policy and
to claim its final performance. Report library-level precision, recall, false
positive rate, incorrect-confident-attribution rate, ambiguity/abstention,
calibration, model drift, query cost and storage cost.

The current noisy-hash ledger is retained as collision triage and an auditable
manual disposition layer. It becomes one input to Hash Discrimination; it is
not treated as the score model or as a blacklist.

## Incremental corpus evidence

`validation/corpus-hash-index.toml` is the authority for the cumulative
cross-batch evidence index. C10 is generation one. Every later sealed cohort
is admitted exactly once by its source-evidence digest and contributes only its
new signature, owner and query observations. Unchanged signatures are not
rescanned.

The index stores append-only batch, signature-owner and signature-batch facts.
Its mutable `signature_state` table is only a rebuildable current-generation
cache. When a new owner is attached to a signature, historical query counts for
that same signature supply the old-query/new-owner false-positive contribution;
new queries are likewise checked against the signature's existing owners. No
unrelated signature is touched. Cross-generation true negatives are derived
from the eligible query-owner population minus observed matches and are never
materialised as non-match rows.

For `B` similarly sized cohorts, rebuilding at every milestone reads
`1 + 2 + ... + B` cohorts, or quadratic repeated input. Delta ingestion reads
each cohort once. Its residual work is proportional to new signature/query
rows plus genuinely shared signature-owner relationships. Exceptionally common
hashes can still have large owner sets; those are real evidence and may be held
as postings rather than expanded into every owner-to-owner pair.

The corpus index is a derived sidecar under `artifacts/hash-discrimination/`.
It never alters a published lane database or a per-run validation database. A
schema or authority change publishes a new sidecar and rebuilds it from retained
evidence instead of migrating either immutable source in place. Each generation
pins its preceding generation digest, authority digest, source-evidence digest
and cumulative counts.

Delta ingestion resolves the six-field signature identity to the corpus
`signature_id` once. Query and owner staging tables are keyed by that integer,
and the roll-up joins them through explicit primary-key lookups. Do not replace
this with an unindexed text-key join: the first C10 attempt demonstrated that
SQLite otherwise selects a nested `SCAN ... LEFT-JOIN` and rereads the same
temporary owner relation for every signature. The query-plan regression test
must continue to reject that plan.

The optional `gpu` dependency adds a WGPU packed-key candidate. C10 compares
its seven-`u32` complete-signature lookup result exactly with the packed CPU
result and records device, buffer, packing, CPU-probe and GPU end-to-end timing.
CPU/SQLite remains publication authority. Missing GPU support, candidate
failure or any mismatch is evidence about the experiment and cannot change the
canonical result. Install the comparison dependency with:

```sh
uv sync --extra gpu
```

## Present implementation boundary

Before the first complete ten-library corpus, the system may expose the
authority, required signals, readiness blockers, planned model generations and
treatment definitions. It must display missing measurements as unavailable,
not as zero, and must not manufacture HDI values.

The first scoring implementation remains blocked until the corpus preserves
the required all-signature denominators, function measurements, candidate-owner
sets and validation contributions. Enabling weighted attribution is a later,
separately reviewed change with an unweighted replay and rollback path.
