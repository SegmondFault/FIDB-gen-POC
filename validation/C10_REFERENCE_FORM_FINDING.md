# C10 reference-form finding

Status: measured and reproducibly sealed on 2026-09-08.  This document records
the result and the decision it supports; it does not by itself change a future
cohort's executable pipeline authority.

## Question

Does a FID reference population built from pre-link static archive members
represent functions in post-link query binaries as well as a reference
population built from whole-archive linked images?

## Controlled comparison

The comparison held these inputs constant:

- ten C libraries and 222 exact build identities per library;
- source validation run `c10-shared-image-symbolic-v2-full`;
- 444 query composites;
- 4,502,211 labelled correct-owner decisions;
- 40,519,899 eligible wrong-owner decisions;
- query analysis, truth maps, FID scoring and decision thresholds; and
- GPU matcher `gpu-portable-fid-v1`, with no fallback in either new arm.

Only the reference population changed:

| Arm | Reference binaries presented to Ghidra |
| --- | --- |
| `archive-only` | Individual relocatable object members from the retained static archives |
| `linked-only` | One non-executed shared image per library/build identity, linked from every retained archive with `--whole-archive` |
| `archive-plus-linked` | The immutable archive and linked candidate indexes searched together |

The linked image uses harness `whole-archive-shared-image-symbolic-v2`.  For
ELF, the fixed adapter uses `-shared`, `-nostdlib` and `--whole-archive`; target
binaries are never executed.  The linked reference is a distinct binary
construction context, not a claim that its FID signatures are a literal
superset of the pre-link signatures.

## Audit chain

The compact, tracked evidence receipt is
[`evidence/c10-reference-form-comparison-v1.json`](evidence/c10-reference-form-comparison-v1.json).
It records the complete confusion matrices, rates, timings, candidate-index and
hash-evidence digests, producer revisions and measured deltas.  Its internal
consistency and authority bindings are tested by
[`../tests/test_reference_form_evidence.py`](../tests/test_reference_form_evidence.py).

| Evidence | Identity |
| --- | --- |
| Comparison authority | `validation/fid-reference-comparison.toml`, SHA-256 `b3a5bf65fc8d930a2143355dcb966160b1acc1e1996a915ed656ed96dca9284a` |
| Linked generation | `c10-linked-reference-v1`, 2,220/2,220 sealed tasks |
| Linked generation digest | `00c11516714457b5b31a7489df67d67c40457c42f21fbdd9f874372a98108219` |
| Linked generation seal | SHA-256 `e9de399f6e67bda70be898bbac842add66ab8d21cbc523492e760c0af8c87e1f` |
| Frozen comparison report | SHA-256 `0e72ae9943c0a2796e409a40d4e6bc2e28d83cea38bed05d1ae76ff3550e3ad0` |
| Frozen comparison seal | SHA-256 `8f49483b4d3570a2edfaa6b92a1521112a35714dbc31d077aea80ac80197c7f5` |

The ignored runtime reports remain under
`artifacts/fid-matching-runs/`; the tracked receipt binds their paths and
digests without putting multi-gigabyte candidate indexes in Git.

The 2,220 terminal task seals span 2026-09-07 20:41:23 UTC through
2026-09-08 00:35:10 UTC: 3h 53m 48s including the stopped pass and its later
resume. Their summed task wall time is 15.94 worker-hours. The final supervisor
status interval, 22:55 through 00:35, describes only the resumed pass and must
not be presented as the complete linked-generation elapsed time.

Recompute and verify the comparison from retained evidence with:

```sh
uv run fidb-poc machine-validation freeze-reference-comparison \
  --project-root . \
  --comparison validation/fid-reference-comparison.toml

uv run python -m unittest \
  tests.test_reference_form_evidence \
  tests.test_fid_reference_comparison -v
```

The freeze command fails closed on an arm report, candidate index, hash-evidence
database, generation seal, authority or decision-population mismatch.  A
second freeze produced the same report and seal digests.

## Result

| Reference population | TP | FP | TN | FN | Precision | Recall | FPR | F1 | Matcher wall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Pre-link archive members | 3,009,968 | 100,128 | 40,419,771 | 1,492,243 | 96.7805% | 66.8553% | 0.2471% | 79.0816% | 500.5 s* |
| Post-link whole-archive images | 4,117,874 | 39,949 | 40,479,950 | 384,337 | 99.0392% | 91.4634% | 0.0986% | 95.1006% | 2,636.3 s |
| Pre-link plus post-link union | 4,122,868 | 40,041 | 40,479,858 | 379,343 | 99.0381% | 91.5743% | 0.0988% | 95.1601% | 3,847.9 s |

`*` The archive timing is from an earlier retained-evidence run and excludes
historical preparation work.  It is not a like-for-like production-cost
measurement.  The linked and union matcher timings are directly comparable.

Changing archive references to linked references produced:

- 1,107,906 additional true positives;
- 1,107,906 fewer false negatives;
- 60,179 fewer false positives;
- 24.6080 percentage points more recall;
- 2.2586 percentage points more precision; and
- 20,796 to 8,621 observed noisy signatures.

Adding the complete archive population back to linked-only produced only 4,994
additional true positives and removed 4,994 false negatives.  It added 92
false positives, increased recall by 0.1109 percentage points and increased
matcher wall time by 1,211.7 seconds (46.0%).

## Interpretation

The validation queries are post-link composite images.  The archive-only
references are pre-link relocatable objects.  Resolving relocations, symbols
and calls changes function bytes and the relationship context used by Ghidra
FID.  Matching pre-link references to post-link queries therefore introduced a
major construct mismatch.  Presenting Ghidra with post-link reference images
removed most of that mismatch.

The small union uplift does not prove that every archive signature is present
in the linked population.  It shows that archive-only candidates add little
**accepted correct-owner evidence for these post-link queries** beyond the
linked population.  Archive signatures unique to relocatable objects may never
occur in the linked queries or may not cross the unchanged FID decision
threshold.

## Decision and limits

The evidence supports this policy for the next C pipeline revision:

1. Use post-link whole-archive references as the canonical searchable form.
2. Preserve C10 archive evidence as an immutable control.
3. Make archive-member Ghidra analysis an explicit sampled/full option, not a
   routine requirement.
4. Keep union search available for ablation and for lanes where independently
   validated marginal benefit justifies its cost.
5. Record reference form, link harness, generation and candidate-index digests
   in every report and export.

This decision does not yet claim ecological recall.  The remaining 384,337
linked-only false-negative decisions (8.54%) require reason-coded analysis, and
the policy must be tested against held-out real executables before release.
Archive-delta reuse, lazy archive escalation and future-cohort pipeline changes
remain separate implementations and must receive their own commits and tests.

### Subsequent implementation choice

The measurements above remain immutable. The later operator decision is to
retain both archive and linked evidence routinely because the union did not
materially reduce precision and pre-link evidence remains useful context. The
new lifecycle compiles each width cell once, consumes its sealed archives to
produce the linked form, and never recompiles merely to make the second
reference representation. `alpha_engine_1` preserves the measured sequential
union path; `alpha_engine_2` is a separately named single-stream implementation
which requires a zero-mismatch canary before promotion. This changes the
future production policy, not the interpretation of the sealed C10 result.

## Implementation history

The following atomic commits form the producer and verification chain:

| Commit | Change |
| --- | --- |
| `dc41e615` | Build resumable C10 linked-reference retrofit |
| `f13c0728` | Propagate reviewed SuperH recovery policy |
| `4a71b3d8` | Bound and recycle linked-reference tasks |
| `4d90d3ad` | Tune the linked-reference worker pool from measured load |
| `066e2d60` | Match sealed FID reference populations |
| `4d9de405` | Verify sealed linked FID generations |
| `21126343` | Add linked-only and union validation arms |
| `ba113eca` | Join sealed query relationships after the canary caught their omission |
| `12c72520` | Reuse immutable indexes instead of building a third union copy |
| `a45a4b89` | Freeze reproducible three-arm comparisons |
| `3175b270` | Record the tracked measured receipt and consistency tests |
