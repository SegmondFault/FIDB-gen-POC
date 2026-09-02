# Exact width batches

This directory binds an already reviewed source selection to an exact compiled
width.  A batch file is planning authority, not permission to execute.  It is
kept separate from `plans/priority-queue.toml` until every selected source has a
matching reviewed native recipe and an operator deliberately materializes and
arms the work.

`c-next-nine-mega-width.toml` is the next run after the OpenSSL width
calibration.  It selects ranks 2–10 from `sources/c-top10-v1.toml`; OpenSSL is
not repeated.  Its locked width is:

- 9 pinned library releases;
- 29 qualified target/compiler-version route profiles;
- 8 distinct compiler identities;
- 6 executable treatments per route: O0, O2, O3, Os, omitted frame pointer,
  and strong stack protection; and
- 174 full-path executions per library, or 1,566 for this batch.

Together with the 174-cell OpenSSL run, that yields 1,740 executions across the
study's top ten.  The broader declared width remains visible in the linked
coverage authority; unimplemented or inapplicable combinations are not silently
counted as executable cells.

## Inspecting the batch

The preview command validates every dependency digest and reports source,
recipe, and execution counts.  It does not download, extract, compile, start
Ghidra, alter the queue, or write a run directory:

```sh
uv run fidb-poc compile-width-batch batch-020 --project-root .
```

The control panel reads the same projection.  Until recipes exist for all nine
libraries it shows the batch as blocked and disarmed, including the exact number
of blocked executions.

## Making it runnable later

For each selected source, add and test a command-free `fidb-recipe/v3` native
recipe whose name, version, URL, and SHA-256 match the source pack.  Add or
generalize fixed build adapters as required by the upstream project; do not put
upstream commands in the batch TOML.  Re-run the preview after every recipe.

When all nine libraries are recipe-ready, the next implementation step is a
materializer that expands the batch into its 1,566 immutable cells.  Only after
a disarmed preview and operator review should that resolved plan be added to
`plans/priority-queue.toml` and armed.  This separation ensures that defining or
editing a batch can never start an expensive run.

Dependency SHA-256 values, the portable route-profile digest, and expected
cardinalities are intentional drift guards. Host-local qualification is reported
separately, so a clean clone can inspect the batch before installing packs. If
the source pack, width authority, compiler set, treatment set, or study changes,
review the new projection and update the pins and expected counts together in one
commit.
