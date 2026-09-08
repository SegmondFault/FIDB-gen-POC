# Database export

**Operations → Export (panel 14)** is the read-only release boundary for FIDB
database packages. The first implementation deliberately does not assemble,
copy, activate or publish anything. It projects existing coordinator results,
lane inventory, lane compatibility authority and hash-discrimination state so
that missing release work cannot be mistaken for a usable package.

The panel distinguishes three things that are currently separate:

- sealed per-cell `.fidb`/`.fidbf` build evidence;
- immutable experimental lane-database generations;
- analyst-admitted lane packs suitable for distribution.

A sealed cell is not an export pack. A raw or compact lane generation is not an
active pack. The build buttons remain disarmed until the release contract below
has an implementation and tests.

## Required release contract

1. Import relationship-complete sealed attempts into immutable lane
   generations, following [`LANE_DATABASES.md`](LANE_DATABASES.md).
2. Select exact generation IDs without mutating their contents.
3. Include `lanes/registry.toml` and the Ghidra/FID compatibility policy needed
   to resolve broad lanes to exact sublanes.
4. Include source, compiler, toolchain, treatment, analysis-policy and seal
   provenance with content digests.
5. Include the selected versioned hash-discrimination/noise overlay as a
   sidecar. Do not copy changing HDI values into an immutable lane generation.
6. Write a release manifest that binds every component path, byte count,
   SHA-256, schema version and generation ID.
7. Reopen the packaged databases and compare representative queries with their
   source generations before publication.
8. Keep publication and consumer activation explicit and reversible.

## Configuration boundary

The eventual exporter must be driven by a reviewed TOML authority under an
`export/` directory. That authority should name the release ID, selected lane
generations and overlay generation, output root, package format, consumer
compatibility target and verification policy. It must not infer those choices
from the current contents of `var/` or silently select “latest”.

No export TOML has been added yet because those fields and the portable package
format have not been frozen. The panel reports this as a blocking gate rather
than inventing a configuration that later code might treat as authoritative.

## Current placement of hash-noise evidence

Noise is **not** embedded in Ghidra's `.fidb` files and it is not currently a
column in an experimental lane database.

- Each machine-validation run writes `hash-evidence.sqlite3`. Its
  `hash_summary` and `hash_signature_owner` tables preserve complete-signature
  outcomes and many-to-many ownership. Its `hash_component_noise`,
  `hash_component_owner` and `hash_component_library` tables preserve separate
  full-hash and specific-hash populations. These tables feed the population and
  false-positive-concentration views in the validation UI.
- `artifacts/hash-discrimination/corpus-index-v2.sqlite3` is the incremental
  cross-batch sidecar. `signature` contains the complete compatibility-scoped
  signature, `signature_owner` links a signature to every library-release
  owner, `signature_state` accumulates owner prevalence and TP/FP/FN evidence,
  and `corpus_generation` makes each admitted batch reproducible.
- The HDI/noise-score formula and reason vocabulary are specified by
  `validation/hash-discrimination.toml`, but numerical per-signature HDI,
  noise-risk and reason rows have not yet been fit. The current corpus sidecar
  is evidence from which those values can be derived; it is not yet the final
  consumer scoring table.

The consumer join key is:

```text
compatibility scope + Ghidra language ID + full hash + specific hash
+ specific-hash additional size + code-unit size
```

This keeps one signature linked to any number of libraries without duplicating
the signature row.

This is row-level deduplication, not several database records pointing to one
`.fidb` file. In the experimental compact lane store, one `compact_signature`
row is referenced by every matching `signature_occurrence`; each occurrence
then resolves through its `build_variant` to the original library release and
provenance. The indexed reverse path is therefore explicit:

```text
signature -> occurrences -> build variants -> library releases/families
```

Native `.fidb` projection is a separate compatibility/output step and may need
to repeat records in the form Ghidra expects. The quality sidecar exists because
noise evidence and scores evolve with every validation cohort, while a released
lane generation and its native projection must remain immutable—not because
reverse ownership is inherently difficult.

## Recommended consumer sidecar

Do not alter Ghidra's native `.fidb` schema to carry changing validation
measurements. Export one compact, read-only SQLite quality sidecar beside the
native databases, containing at least:

- `score_generation`: method/config/code/evidence digests and cohort boundary;
- `signature_quality`: the complete key, HDI, noise risk, confidence, reason
  category, reason confidence and observed TP/FP/FN/owner counts;
- `signature_owner`: the many-to-many library/release ownership links;
- `component_quality`: separate full-hash and specific-hash prevalence and
  false-positive contribution;
- `metadata`: schema, compatibility, source corpus generation and checksums.

a downstream maintainer or another consumer can then take the hashes exposed by a FID match,
look up one complete-signature row, show its relative noise and owners, and use
the score as evidence quality without changing Ghidra's matching database. A
small integration helper or documented SQL view should ship with the bundle so
consumers do not have to reconstruct the join or scoring policy themselves.
