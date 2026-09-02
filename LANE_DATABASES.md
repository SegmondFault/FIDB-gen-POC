# Experimental lane databases

The lane system is an additive, reversible experiment. It does **not** replace,
activate, mutate or delete the existing per-cell Ghidra FID databases. Generated
lane files live below ignored `var/fidb-lanes/`; the reviewed definitions live in
Git.

## Boundary model

A lane is the database/pack boundary an analyst understands. A sublane is the
exact compatibility boundary the integration resolves from the binary and the
Ghidra program:

```text
analyst selects or installs one broad lane
    linux-x86
      -> linux-x86-elf32
      -> linux-x86-elf64

program facts select the sublane
    format + machine/ISA + bits + endianness + OS/ABI
    + Ghidra LanguageID + CompilerSpecID + FID analysis policy
```

For example, Linux x86-32 and x86-64 belong to the single `linux-x86` lane;
Windows PE32 and PE64 belong to `windows-x86`. Compiler family/version,
treatment, library and release are occurrence provenance within a sublane. They
do not force the analyst to choose another database.

`lanes/registry.toml` is the closed-schema authority. Its current entries are
all `experimental`. `resolve_program_sublanes()` accepts inspected program
facts: one match is exact, multiple matches are explicitly ambiguous, and no
match is unsupported. It never guesses a sublane from partial evidence.

## What is implemented

- a versioned registry of broad lanes, exact sublanes and the pinned Ghidra/FID
  policy;
- target-to-sublane and inspected-program resolution;
- an immutable raw SQLite generation which preserves every signature
  observation and all occurrence provenance without deduplication;
- a preview-first compiler for measured width-run signature ledgers;
- a standalone, dry-run-by-default deduplication experiment;
- read-only local-API and control-panel visibility.

The raw SQLite database is evidence and interchange state, not a native Ghidra
`.fidb`/`.fidbf`. Native projection is intentionally recorded as
`blocked-missing-relationships` for the current JSONL evidence because those
ledgers do not retain every Ghidra FID function relationship needed to prove a
faithful reconstruction. No lane pack is active or approved for analyst use.

## Preview and build a raw generation

All examples run from the repository root. Registry inspection is read-only:

```sh
uv run fidb-poc lane registry
```

Preview one lane from an existing measured-complete width run. This validates
the run, manifests, target/route mapping, Ghidra policy, paths and digests, but
does not read all signature records or write a database:

```sh
uv run fidb-poc lane compile \
  --run artifacts/width-runs/c-width-v1/RUN_ID \
  --lane linux-x86
```

Writing requires both an explicit execution switch and a new generation ID:

```sh
uv run fidb-poc lane compile \
  --run artifacts/width-runs/c-width-v1/RUN_ID \
  --lane linux-x86 \
  --generation linux-x86-experiment-001 \
  --execute
```

The default output is
`var/fidb-lanes/linux-x86/linux-x86-experiment-001.raw.sqlite3`. The compiler
refuses paths outside the project and refuses to replace an existing output.
Inspect a raw generation read-only with:

```sh
uv run fidb-poc lane inspect \
  var/fidb-lanes/linux-x86/linux-x86-experiment-001.raw.sqlite3
```

## Deduplication is a separate experiment

Raw generations do not deduplicate. `scripts/deduplicate_lane_db.py` is
standalone and uses only the Python standard library so its schema, key and SQL
can be audited without following application abstractions. Its default action
is a read-only count preview:

```sh
uv run python scripts/deduplicate_lane_db.py \
  var/fidb-lanes/linux-x86/linux-x86-experiment-001.raw.sqlite3
```

Add `--show-sql` to print the complete compact schema and transformation. A
compact copy is written only with all three explicit arguments:

```sh
uv run python scripts/deduplicate_lane_db.py \
  var/fidb-lanes/linux-x86/linux-x86-experiment-001.raw.sqlite3 \
  --output var/fidb-lanes/linux-x86/linux-x86-experiment-001.compact.sqlite3 \
  --generation linux-x86-compact-experiment-001 \
  --execute
```

The script refuses in-place operation and existing output paths. It shares only
the exact signature key printed in its source and preserves one occurrence row
for every raw observation. Compact signatures start `unreviewed`, awaiting the
held-out ecological validation described below. No real campaign data has yet
been compacted by this implementation.

## Gates before use

1. Extend worker evidence to preserve complete function relationships and all
   metadata needed for a native Ghidra projection.
2. Build native databases from admitted programs and prove query equivalence
   against the original per-cell databases.
3. Run ecological validation on held-out real binaries, including binaries that
   contain no enrolled library, and measure false positive function matches.
4. Review collisions/shared ownership and assign admission decisions.
5. Publish checksummed immutable packs and only then add an explicit activation
   mechanism for BSimVis or another consumer.

Until those gates pass, the GUI must continue to show zero materialized/active
packs and the existing per-cell databases remain the only operational result.

## Rollback and recovery

There is currently no activation switch to undo: existing build, queue and query
paths do not consume lane databases. To abandon the experiment safely:

1. Stop creating new lane generations. No current worker or queue needs to be
   stopped.
2. Preserve any generated `var/fidb-lanes/` directory as experimental evidence,
   or remove it only after an explicit data-retention decision. It is ignored by
   Git and is not an input to the existing worker.
3. Revert the feature commits in reverse chronological order. The deduplication
   experiment is isolated in `64a1fbf` and can be reverted alone. The remaining
   implementation commits are `19f9068`, `cff79ea`, `d20305b`, `da9ac8f`,
   `1b5f8bc`, `77fccb8`, `7bfbe91` and `b55b73d`.
4. Run the ordinary unit/format/control-panel checks. The original per-cell
   FIDB/FIDBF artifacts and width evidence are untouched and require no restore.

Prefer `git revert` over history rewriting on a shared branch. If the experiment
is redesigned rather than abandoned, add a new schema version and compiler;
never reinterpret an existing immutable generation in place.
