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

## Time-aware block projection

`performance/batch-planning.toml` projects this campaign into five nominal
blocks capped at five estimated hours on `reference-host-94g-balanced`:

| Block | Libraries | Nominal estimate | Executions | Android |
| --- | --- | ---: | ---: | ---: |
| 01 | SQLite + Readline | 4.77 h | 444 | 96 |
| 02 | gettext/libintl + LZ4 | 4.58 h | 444 | 96 |
| 03 | nghttp2 + OpenSSL Android gap | 4.13 h | 270 | 96 |
| 04 | GMP + XZ | 4.65 h | 444 | 96 |
| 05 | PCRE2 + Zstandard | 4.94 h | 444 | 96 |

The central total is 23.08 hours. The deliberately broad ±40% planning range
is 13.85–32.31 hours because only OpenSSL supplies direct machine evidence;
the upper range is risk visibility, not a claim that every block will finish
within five real hours. The packing ceiling applies to the central estimate.
Each completed library should replace part of the source-size heuristic with
observed duration evidence.

Inspect or compare a performance profile without queueing work:

```sh
uv run fidb-poc plan-time-blocks --project-root .
uv run fidb-poc plan-time-blocks --project-root . \
  --performance-profile reference-host-112g-throughput
```

The projection recomputes from exact applicability, treatment-relative cost,
library source size, measured cells/hour and worker scaling. Adding a compiler,
route, treatment or artifact/replay multiplier therefore increases the work
rather than inheriting a stale hand-entered ETA. Before materialization, freeze
the block membership, selected profile and plan digest; a queued campaign must
never repack itself as later evidence updates the draft projection.

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
materializer that expands both segments into their 2,046 immutable new cells
and binds each cell to the reviewed five-block projection.
Only after a disarmed preview and operator review should the resolved campaign
be added to `plans/priority-queue.toml` and armed. This separation ensures that
defining or editing a batch can never start an expensive run.

Dependency SHA-256 values, the portable route-profile digest, and expected
cardinalities are intentional drift guards. Host-local qualification is reported
separately, so a clean clone can inspect the batch before installing packs. If
the source pack, width authority, compiler set, treatment set, or study changes,
review the new projection and update the pins and expected counts together in one
commit.
