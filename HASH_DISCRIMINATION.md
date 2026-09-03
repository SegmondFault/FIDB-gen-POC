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

Observed facts and inferred explanations remain separate. Initial reason
categories are compiler/runtime boilerplate, widespread cross-library reuse,
library-family or common-ancestry reuse, cross-language reuse, trivial/small
function, empirically misleading attribution, unexplained ambiguity and
insufficient evidence. Unknown is the safe default.

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

## Present implementation boundary

Before the first complete ten-library corpus, the system may expose the
authority, required signals, readiness blockers, planned model generations and
treatment definitions. It must display missing measurements as unavailable,
not as zero, and must not manufacture HDI values.

The first scoring implementation remains blocked until the corpus preserves
the required all-signature denominators, function measurements, candidate-owner
sets and validation contributions. Enabling weighted attribution is a later,
separately reviewed change with an unweighted replay and rollback path.
