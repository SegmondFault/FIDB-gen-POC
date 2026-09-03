# Exact width batches

This directory binds an already reviewed source selection to an exact compiled
width.  A batch file is planning authority, not permission to execute.  It is
kept separate from `plans/priority-queue.toml` until every selected source has a
matching reviewed native recipe and an operator deliberately materializes the
work. Materialization and arming remain separate decisions.

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

The control panel reads both projections. All nine new libraries now have
source-matching reviewed recipes, so `batch-020` reports 9/9 recipe-ready and
1,998 materializable executions. The Android gap reports 48 more. Both remain
independently disarmed as input authorities; their combined output is now the
five-block materialized campaign below.

## Materialized campaign

The nine command-free `fidb-recipe/v3` recipes and their fixed adapters are now
present and compilation-qualified at the target-family and oldest-generation
edges described in `recipes/README.md`. Their name, version, URL, and SHA-256
match the source pack; no upstream commands live in the batch TOML.

`fidb-poc materialize-batches` expands the two authorities through a
`width-native` plan matrix, preserving all 37 compiler-generation routes rather
than collapsing them to the 17 ordinary worker route templates. It checks that
every route is qualified, the applicability set is rectangular and executable,
every native recipe matches its source pin, every cell resolves unblocked, and
the total is exactly 2,046. The generated plans and manifest live under
`plans/materialized/c-top10-nonapple-width-v2/`.

```sh
# Read-only proposed materialization
uv run fidb-poc materialize-batches --project-root .

# Verify checked-in plans and manifest byte-for-byte
uv run fidb-poc materialize-batches --project-root . --check

# Deliberately regenerate after reviewing changed authorities
uv run fidb-poc materialize-batches --project-root . --write
```

The five plans are registered in `plans/priority-queue.toml` with a plan-file
SHA-256, exact execution count, and portable ordered-cell digest. File drift is
rejected while loading the queue; route, treatment, recipe, cardinality or
blocked-cell drift is rejected before coordinator synchronization mutates its
ledger. The queue remains `armed = false`, so materialization and synchronization
still cannot start an expensive run.

To reverse the experiment, leave the queue disarmed, remove the five block IDs
and `[[batch]]` rows from `plans/priority-queue.toml`, and remove the generated
campaign directory. If a disarmed queue was already synchronized, synchronizing
the reduced queue deactivates those jobs while retaining the append-only audit
history; it does not delete evidence. No source, toolchain cache, completed
OpenSSL artifact, or lane database depends on the generated plans.

Dependency SHA-256 values, the portable route-profile digest, and expected
cardinalities are intentional drift guards. Host-local qualification is reported
separately, so a clean clone can inspect the batch before installing packs. If
the source pack, width authority, compiler set, treatment set, or study changes,
review the new projection and update the pins and expected counts together in one
commit.
