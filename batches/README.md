# Exact width batches

This directory binds an already reviewed source selection to an exact compiled
width.  A batch file is planning authority, not permission to execute.  It is
kept separate from `plans/priority-queue.toml` until every selected source has a
matching reviewed native recipe and an operator deliberately materializes and
arms the work.

The next top-ten campaign has two disarmed segments so completed OpenSSL work
is not repeated:

- `c-next-nine-mega-width.toml` selects ranks 2–10 and applies all 37 qualified
  non-Apple routes in `c-width-v2`;
- `c-openssl-android-gap.toml` selects only OpenSSL and applies the eight
  Android routes that were absent from its completed `c-width-v1` run.

The expanded locked width is:

- 9 pinned library releases;
- 37 qualified target/compiler-version route profiles;
- 10 distinct compiler identities;
- 6 executable treatments per route: O0, O2, O3, Os, omitted frame pointer,
  and strong stack protection; and
- 222 full-path executions per new library, or 1,998 for the next-nine batch;
  plus 48 Android-only OpenSSL executions.

The campaign therefore schedules 2,046 new executions. Together with the 174
completed OpenSSL cells, it yields 2,220 route/treatment executions across the
study's top ten: 10 libraries × 37 routes × 6 treatments. The broader declared
width remains visible in the linked coverage authority; unimplemented or
inapplicable combinations are not silently counted as executable cells.

## Inspecting the batch

The preview command validates every dependency digest and reports source,
recipe, and execution counts.  It does not download, extract, compile, start
Ghidra, alter the queue, or write a run directory:

```sh
uv run fidb-poc compile-width-batch batch-020 --project-root .
uv run fidb-poc compile-width-batch batch-020-android-gap --project-root .
```

The control panel reads both projections. Until recipes exist for all nine new
libraries it shows `batch-020` as blocked and disarmed, including the exact
number of blocked executions. The Android gap is recipe- and toolchain-ready,
but remains separately disarmed by policy.

## Making it runnable later

For each selected source, add and test a command-free `fidb-recipe/v3` native
recipe whose name, version, URL, and SHA-256 match the source pack.  Add or
generalize fixed build adapters as required by the upstream project; do not put
upstream commands in the batch TOML.  Re-run the preview after every recipe.

When all nine libraries are recipe-ready, the next implementation step is a
materializer that expands both segments into their 2,046 immutable new cells.
Only after a disarmed preview and operator review should the resolved campaign
be added to `plans/priority-queue.toml` and armed. This separation ensures that
defining or editing a batch can never start an expensive run.

Dependency SHA-256 values, the portable route-profile digest, and expected
cardinalities are intentional drift guards. Host-local qualification is reported
separately, so a clean clone can inspect the batch before installing packs. If
the source pack, width authority, compiler set, treatment set, or study changes,
review the new projection and update the pins and expected counts together in one
commit.
