# FIDB worker proof of concept

This repository is a small, inspectable proof of concept that builds Ghidra
Function ID databases for two pinned C libraries on one native Linux toolchain.
It demonstrates a constrained path from a library name to a non-empty FIDB and a
CSV evidence manifest:

```text
library name
  -> reviewed, hash-pinned recipe
  -> source download and SHA-256 verification
  -> fixed Python build adapter
  -> native GNU GCC compilation and ELF validation
  -> Ghidra analysis and FID generation
  -> one FIDB and one manifest row per build cell
```

The caller supplies a library name, the configured route and a treatment. It
cannot supply a URL, compiler command or shell fragment.

## Demonstrated scope

The supported demonstration is deliberately narrow:

- host and target: native Linux x86-64;
- toolchain: `/usr/bin/gcc`, `/usr/bin/ar` and `/usr/bin/ranlib` (the validated
  Fedora host used GNU GCC and GNU binutils);
- Ghidra language and compiler specification: `x86:LE:64:default` and `gcc`;
- libraries: zlib 1.3.1 and bzip2 1.0.7;
- treatment: `baseline_o2` (`-O2`, compiled without `-g` or LTO, frame pointer
  retained); and
- profile: `smoke`.

The latest local end-to-end validation completed both libraries on Fedora Linux
x86-64 with native GNU GCC. Its Ghidra installation metadata reported version
12.1.2 and release name `DEV`; it must not be represented as an official Ghidra
12.1.2 release. Evidence intended for sharing should identify the actual Ghidra
build recorded by the generated manifest.

macOS, Windows, cross-compilers, non-x86 processors, alternate optimization
treatments and arbitrary upstream projects are outside this PoC's supported and
validated scope. The GNU identity check uses the `Free Software Foundation`
copyright marker instead of a distribution-specific first-line banner. This is
compatible with conventional Fedora, Arch, Debian and Ubuntu GCC output, but the
successful validation above is the claim being made—not a multi-distribution test
matrix.

The two reviewed recipes exercise different upstream build shapes:

| Library | Version | Build shape | Worker adapter |
| ------- | ------: | ----------- | -------------- |
| zlib | 1.3.1 | Autoconf | fixed Autoconf adapter |
| OpenSSL | 3.5.8 | OpenSSL Configure | fixed static-library adapter |
| bzip2 | 1.0.7 | Make | fixed Make adapter |

## Requirements

Run the PoC from the repository's source checkout. The Python wheel is not a
standalone distribution: runtime configuration, recipes and Ghidra scripts remain
checkout-local.

The host needs:

- Linux x86-64;
- Python 3.10 or newer and [`uv`][1];
- native GNU GCC at `/usr/bin/gcc`, `ar` and `ranlib` at `/usr/bin/ar` and
  `/usr/bin/ranlib`, plus `make`, a POSIX `sh`, and `file`;
- Ghidra with `support/analyzeHeadless` plus the compatible PyGhidra components;
  and
- Java 21.

`GHIDRA_HEADLESS` is required for the supported Linux run; the worker does not
auto-discover Linux Ghidra installations. Set it to a path valid in the shell
that runs the worker. A host installation might use:

```sh
export GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless
```

If the same host installation is mounted into a Toolbx or other container, its
path may instead be:

```sh
export GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless
```

The `/run/host` path is container-specific and should not be used from the host
shell. If Java 21 is not on `PATH`, set `JAVA_HOME` to its JDK directory. Some
containers may also require `JDK_JAVA_OPTIONS=-XX:-UseContainerSupport` for Java
home discovery; it is not normally needed on the host.

## Run the demonstration

From the repository root, install the locked Python environment, inspect the plan
and check the configured tools:

```sh
uv sync --locked

uv run fidb-poc \
  --plan \
  --route linux-x86_64-gnu-gcc \
  --profile smoke

uv run fidb-poc \
  --doctor \
  --route linux-x86_64-gnu-gcc
```

Then run a clean end-to-end build:

```sh
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
  uv run fidb-poc --fresh \
    --route linux-x86_64-gnu-gcc \
    --profile smoke
```

With no `--library`, the worker uses the name-only request queue in `worker.toml`
and builds both libraries. To build only zlib, add `--library zlib`. A successful
two-library run ends with:

```text
Result: complete=2
Manifest: .../artifacts/libs/fidb_manifest.csv
```

A real build exits nonzero if any requested cell does not reach `complete`, so
shell automation and CI cannot mistake a printed `build_failed` or `fid_failed`
result for success. `--plan` performs no download, compilation or Ghidra work.

## Run the notebook

The walkthrough in `notebooks/demo.ipynb` uses the optional notebook dependency
group. From the repository root, install that group and start Jupyter with the
project environment and the host Ghidra path:

```sh
uv sync --locked --group notebook

GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
  uv run --group notebook jupyter lab notebooks/demo.ipynb
```

Inside Toolbx, use
`GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless` instead. If that
container cannot discover Java correctly, also set
`JDK_JAVA_OPTIONS=-XX:-UseContainerSupport` as described above. Start Jupyter
from the repository root so the notebook uses this checkout and its locked
environment.

The notebook executes a real zlib build and a LanguageID diagnostic probe. It
therefore recreates `work/` and `artifacts/libs/`, including a candidate FIDB, CSV
reports and a PNG chart. Remove those generated directories after the demo when
preparing a source-only handoff.

## Inputs, evidence and temporary outputs

`recipes/*.toml` (`mode="native"`) is the reviewed source catalogue for this
worker. Each recipe declares the canonical name and version, archive URL and
SHA-256, expected source markers, build system and expected static archive.
A recipe cannot contain a command. Every recipe in this repository -- native
library, libc, or malware fork alike -- uses this same `fidb-recipe/v3` TOML
schema; only the directory and `mode` differ. See **Hunting an unknown
target** below for the other two.

The earlier, source-only staging boundary is [`sources/c-top10-v1.toml`](sources/c-top10-v1.toml).
It pins and checksum-identifies all ten study archives independently of build
behavior. All ten pins now have matching command-free native recipes; see
[`recipes/README.md`](recipes/README.md) for their fixed adapters and
compilation-only qualification boundary. Inspect or acquire the pack without
extraction, compilation, or Ghidra work:

```sh
uv run fidb-poc source status c-top10-v1 --project-root .
uv run fidb-poc source pull c-top10-v1 --project-root .
```

Verified bytes are stored content-addressed under the ignored
`var/fidb-sources/downloads/` cache. See [`sources/README.md`](sources/README.md)
for the extension and trust model.

## Continuous machine validation

The first ten-library cohort has a frozen, seeded five/five validation design
in [`validation/machine-validation.toml`](validation/machine-validation.toml).
Its live width is compiled from every applicable route/compiler/
treatment identity, so newly added variables automatically become required
inputs. Inspect the admission gate without changing the active build queue:

```sh
uv run fidb-poc machine-validation status --project-root .
```

After a production batch drains, the worker performs the same read-only check.
Once all cohort libraries are complete it automatically materialises a separate
`validation-run` and registers it in
[`plans/validation-schedule.toml`](plans/validation-schedule.toml). The first
real validation remains claim-blocked for a post-cohort canary. Normal cohorts
contain ten libraries; a final 2--9-library remainder requires an explicit,
justified TOML override. See [`validation/README.md`](validation/README.md) for
the split, TP/FP/TN/FN report and collision/miss evidence contract.

The split RNG is not process-random. Its checked-in `randomization.seed` is a
32-byte hexadecimal authority and `sha256-ranked-v1` deterministically ranks
the canonical pinned library IDs. Loading fails if the recorded folds differ
from that seed, so rerolling requires an explicit TOML and Git change.

Held-out real binaries use the separate
[`validation/ecological-validation.toml`](validation/ecological-validation.toml)
authority and **Ecological validation** control-panel page. Imports are
SHA-256 pinned and never executed, automatically routed to a compatible lane,
and checked against every library owner in its latest compatible corpus
generation. Labelled cases report TP/FP/TN/FN at binary/library-presence level
with function-level collision and miss evidence; unlabelled exploratory cases
do not manufacture confusion counts.

The control panel groups these workflows under **Validation** and adds a
**Hash discrimination** workspace. Its initial noisy-hash ledger combines
recurring collision evidence from machine and ecological reports within the
exact query-compatible sublane, marks one-off candidates separately from
cross-run recurrence, and requires a reasoned TOML disposition. The broader
Hash Discrimination Index will measure how strongly each signature supports
library provenance, compare unweighted, exclusion, down-weighted and contextual
treatments, and remain explicitly unscored until sufficient corpus evidence
exists. Decisions never rewrite published evidence; `quarantine` is a
forward-admission contract until the lane builder consumes it. See
[`HASH_DISCRIMINATION.md`](HASH_DISCRIMINATION.md) for the model boundary and
[`validation/README.md`](validation/README.md) for operational authorities.

The disarmed next-run campaign is split between
[`batches/c-next-nine-mega-width.toml`](batches/c-next-nine-mega-width.toml) and
[`batches/c-openssl-android-gap.toml`](batches/c-openssl-android-gap.toml).
Ranks 2–10 receive `c-width-v2`: 9 libraries × 37 qualified compiler routes ×
6 executable treatments = 1,998 executions. OpenSSL receives only its 8 newly
qualified Android routes × 6 treatments = 48 executions, without repeating its
174 completed cells. The next campaign is therefore 2,046 new executions and
the complete top-ten projection is 2,220. Inspect both pinned authorities and
their current readiness without starting work:

```sh
uv run fidb-poc compile-width-batch batch-020 --project-root .
uv run fidb-poc compile-width-batch batch-020-android-gap --project-root .
```

Both segments are source-, recipe-, and toolchain-ready. The reviewed
materializer has frozen them into five plans under
[`plans/materialized/c-top10-nonapple-width-v2/`](plans/materialized/c-top10-nonapple-width-v2/)
and registered the exact 2,046-cell order in `plans/priority-queue.toml`. The
generated plans remain disarmed authorities. The live priority queue was
explicitly armed on 2026-09-03 after recovery preflight and canaries. Preview
or verify materialization without synchronizing a ledger or starting work:

```sh
uv run fidb-poc materialize-batches --project-root .
uv run fidb-poc materialize-batches --project-root . --check
uv run fidb-poc auto-batches --project-root . --check
```

`--write` is the deliberate regeneration boundary after an authority change.
It atomically replaces the generated plans and manifest but still cannot arm,
synchronize, claim, or execute work. See [`batches/README.md`](batches/README.md)
for the drift guards, review process, and rollback boundary.

The active auto-batched campaign keeps each library/route's six treatments
together and produces 23 roughly one-hour chunks. Its generated queue remains
disarmed under `plans/auto-materialized/`; the reviewed active copy is
`plans/priority-queue.toml`, while
`plans/c-top10-nonapple-width-v2-queue-policy.toml` remains the stable generator
input. Chunks are manually triggerable one at a time outside the timer and chain
during 00:00–05:30 without cutting off a started chunk.

### Portable performance profiles

[`performance/profiles.toml`](performance/profiles.toml) keeps cell concurrency,
nested compiler jobs and embedded-Ghidra JVM bounds in one reviewed authority.
The `auto` default detects physical cores and SMT siblings separately, honours
affinity/cgroup ceilings, and bounds the result independently by OS-visible
RAM. Explicit
profiles cover 8/16/32 GiB laptops, the current 94 GiB `reference-host` allocation,
a 112 GiB throughput allocation, and the 64 GiB M1 Max external host. Inspect
them without running work:

FIDB runtime and operator configuration is stored as TOML. The GUI keeps no
independent performance configuration: its **Performance** page projects host
detection, the automatic recommendation, the active queue profile and any
setting-level differences from `performance/profiles.toml` and the queue TOML.
JSON is used only for API projections and evidence/output records.

```sh
uv run fidb-poc performance --project-root .
uv run fidb-poc performance auto --resolve-auto --project-root .
uv run fidb-poc run-width --project-root . --canary \
  --performance-profile laptop-4c-8g
```

The second command is still a preview because it omits `--execute`. Profile IDs
are written into run/benchmark evidence. `-Xmx` is a JVM maximum, not an eager
per-worker reservation; portable profiles are starting points until benchmarked
on their named host class. The control panel exposes this authority under
**Performance** and keeps measured execution evidence under **Timing**. See
[`performance/README.md`](performance/README.md) for selection,
hardware interpretation and qualification.

An optional staged-backend benchmark can separate compiler work from a bounded
long-lived Ghidra pool and compare either a Python or Rust supervisor against a
normal-run result. It is disarmed by default and does not alter queue execution.
The fixed OpenSSL qualification found no meaningful Rust throughput advantage;
see [`performance/README.md`](performance/README.md#staged-backend-experiment)
and [`experiments/rust-staged/README.md`](experiments/rust-staged/README.md).

`worker.toml` is trusted operator configuration for the single Linux route, one
treatment and one profile. It is not untrusted request data.

### Declarative plan requests

[`plans/coverage-baseline.toml`](plans/coverage-baseline.toml) is a human-readable
`fidb-plan/v1` request. It selects only reviewed recipe, route, treatment and
toolchain identities; it cannot contain a URL, hash, compiler flag, adapter or
raw command. Resolve it without downloading or executing anything:

```sh
uv run fidb-poc resolve-plan plans/coverage-baseline.toml \
  --output work/plans/coverage-baseline.json
```

The canonical JSON expands the requested matrices and named factor variants,
records blocked desired coverage as well as runnable cells, snapshots the
sensitivity catalog, and adds a deterministic plan digest. The plan's
`max_cells` policy applies to the full factor cross-product. Toolchain
installation is a later readiness check: a reviewed but currently unavailable
toolchain remains visible in the plan.

Cross-toolchain and prebuilt-library inputs use one ignored, content-addressed
cache at `var/fidb-toolchains/downloads/`. Inspect it without mutation, or
acquire a reviewed registry identity explicitly:

```sh
uv run fidb-poc toolchain status \
  --id uclibc@2017.05:powerpc-e500mc-bootlin-2017.05 --input toolchain
uv run fidb-poc toolchain acquire \
  --id uclibc@2017.05:powerpc-e500mc-bootlin-2017.05 --input toolchain
```

The command accepts registry identities, never caller-supplied URLs or hashes.
Workers serialize acquisition by digest, apply bounded timeouts and retries,
stream and verify SHA-256, quarantine invalid existing bytes, fsync the payload,
and publish it by atomic rename. Extraction and compilation remain isolated in
each attempt; only the immutable verified input is shared.

### Portable toolchain profiles

The broader width study uses language-scoped profiles rather than a collection
of machine-local installation notes. C libraries are the active campaign;
C++ is included where an in-scope library requires it. The transport and
worker model are language-neutral so later languages can add their own finite
profiles and reviewed probes without inheriting C's multiplier.

The `c-top10-linux` profile implements ten ordered target requirements: eight
Bootlin GCC routes and an llvm-mingw Windows route are managed from Linux;
native Apple Clang runs as a separately registered macOS ARM64 worker. Inspect
or prepare the Linux-managed side with:

```sh
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
./scripts/toolchains/pull.sh c-top10-linux
./scripts/toolchains/prepare.sh c-top10-linux
./scripts/toolchains/compose.sh c-top10-linux
./scripts/toolchains/qualify.sh c-top10-linux
```

All operations emit stable JSON. `plan` and `status` are read-only. The mutation
commands form a fixed lifecycle: checksum-pinned pull, traversal-safe
preparation, optional reviewed composition, and fixed route-specific
qualification. They accept reviewed IDs, never caller-supplied URLs or
commands. The nine archives total 753,465,840 bytes compressed; their safely
extracted files measured 3,852,132,920 bytes on 2026-09-02.

All nine Linux-managed routes passed their fixed C, C++17, target-object, and
static-archive qualification probes on `reference-host`. The committed audit
snapshot is
[`toolchains/evidence/c-top10-linux-reference-host-2026-09-02.toml`](toolchains/evidence/c-top10-linux-reference-host-2026-09-02.toml).
The Apple route remains deliberately external and unqualified, and no library
batch was run as part of this qualification.

The public project does not copy or redistribute Xcode or an Apple SDK. The
definition in `toolchains/external/` keeps those tools on Apple hardware and
records platform, Xcode, SDK, compiler, Ghidra, Java, resource, and language
capabilities before the worker may register. A deliberately disarmed zlib
canary is present for later review; repository preparation does not start a
worker or run it. The optional `c-top10-reference` profile additionally keeps
native MSVC as distinct Windows reference evidence.

See [`TOOLCHAINS.md`](TOOLCHAINS.md) for the complete operator setup, native
Mac result handoff, and public/legal boundary. See
[`toolchains/README.md`](toolchains/README.md) for the authority layers,
extension workflow, state vocabulary, safety contract, and machine/LLM-facing
interface.

The optional `[queue]` table controls deterministic materialization order. Its
`recipe_order` is the left-hand build order; `strategy` chooses whether all
factor variants for one recipe run together or one variant is swept across all
recipes first. The resolved `queue_preview` is immutable plan intent, not live
coordinator state: a coordinator may later queue, lease, pause or reprioritize
those execution identities while retaining an event trail back to this plan.
In the operator UI, batch ordering supplies effective priority and regenerates
this preview; batch membership and live queue state are coordinator overlays,
not additional recipe provenance fields.

[`sensitivity/factors.toml`](sensitivity/factors.toml) records the controlled and
measured inputs known or expected to affect FID output, while
[`sensitivity/variants.toml`](sensitivity/variants.toml) gives those factors named,
checkable coverage choices without exposing raw compiler commands. Executor
remains routing provenance and is deliberately not a sensitivity treatment.
The current report audit yields 41 operational dimensions: 13 independently
varied build factors, two repeat controls, and additional provenance, recovery,
environment, truth, matching and admission controls. The report's number 23 is
the count of treatment slugs, not a factor total. The 41-row catalogue is a
versioned baseline, not a claim that sensitivity discovery is complete; known
but unsupported dimensions remain visible and unmodeled until a reviewed
variant and execution route exist. Compound comparisons and outcome metrics are
kept out of the primitive factor count.
The top-level `[coverage].factor_variants` provides defaults; a matrix may set
its own `factor_variants` array so a crosspoint selection can vary precisely by
library or workload. An omitted matrix field inherits the default, while an
explicit empty array selects one unvaried execution for that matrix.

The resolved document also overlays the current artifact inventory. A cell is
reported as `built` only when `artifacts/runs` contains a matching cell seal and
both its FIDB and FIDBF still match the sealed paths, sizes and SHA-256 digests.
A loose FIDB without that seal is only `artifact-only`; a completed batch or
ledger row is never enough by itself. Inventory is deliberately excluded from
the plan digest so existing output state cannot change the requested build
identity.

### Automatic priority queue

[`plans/priority-queue.toml`](plans/priority-queue.toml) is the ordered automation
authority. Its `batch_order` is the priority list: workers claim the first
runnable cell in the first batch, skip blocked coverage, and continue down the
list. Each batch points to a reviewed `fidb-plan/v1` document. The queue is
normally disarmed between campaigns; this recovery run was deliberately armed
on 2026-09-03. The next five entries are the materialized top-ten width blocks.
Each pins both the generated plan bytes and a portable digest of its ordered
resolved cell identities; queue synchronization fails before its transaction if
either has drifted.

Synchronize and inspect its durable state without executing anything:

```sh
uv run fidb-poc queue sync
uv run fidb-poc queue status --full
uv run fidb-poc queue resolve-preflight
uv run fidb-poc queue doctor --include-inactive --services
```

`queue doctor` is the read-only incident entry point. It collects a coherent
ledger snapshot, failure/stage fingerprints, worker-unit drift and guarded
recovery candidates without changing the queue. Follow
[`operations/RECOVERY_RUNBOOK.md`](operations/RECOVERY_RUNBOOK.md) for the
containment, canary, evidence-preserving requeue and rollback sequence.

The resolution preflight is an execution-free gate over the exact active ledger
jobs. It uses the worker's canonical runtime resolver, including versioned width
routes and compiler identities, but performs no compilation and starts no JVM.
Every active job must pass before the queue is armed.

A reviewed recovery never edits or clears the ledger. While the queue is
disarmed, paused and has no live leases, requeue an exact terminal failure set
with an explicit cardinality guard. There may be no active admission for a
different batch; the selected batch itself may remain admitted so its untouched
cells and repaired failures can resume together:

```sh
uv run fidb-poc queue requeue-failed \
  --batch BATCH_ID --expected-count COUNT --reason "reviewed repair"
```

The transition preserves every attempt and stage record, appends a per-job
operator event plus a batch summary and leaves the attempt counter intact.
Consequently the recovered claim becomes the next numbered attempt instead of
rewriting history.

The worker unit bounds each Ghidra process by memory and tasks. An OpenSSL
Android ARM64/O0 cell importing 1,129 objects exhausted both the former 512 and
1,024 task limits before exhausting either the 4 GiB Java heap or host RAM. A
single-worker qualification observed 1,103 live tasks and sealed the complete
cell in 458.379 seconds under `TasksMax=2048`, with the 8 GiB memory limit
unchanged. Diagnose `unable to create native thread` against
`TasksCurrent`/`TasksMax` before treating it as a heap failure.

After an operator deliberately changes `armed` to `true`, one or more workers
can consume it continuously:

```sh
systemctl --user enable --now fidb-library-local-workers.target
```

The active queue is deliberately library-only: native cells, source-library
cells with the explicit `local` executor, and typed `archive-library` cells
which only extract objects from a pinned static archive. Archive cells have no
source executor choice and record `archive-local` routing. The typed
`library-local` worker pool fails closed against QEMU and malware cells even if
a later queue edit places one before an eligible library cell. The queue binds
the measured `reference-host-94g-balanced` profile; its twenty service processes,
four build jobs per cell and 4 GiB JVM ceiling are one reviewed policy rather
than independent knobs. Queue loading fails if `max_workers` drifts from that
profile.

TOML remains the source of requested coverage and priority. The ignored local
SQLite ledger at `var/fidb-coordinator/ledger.sqlite3` records only runtime
state: claims, fenced leases, attempts, stages, failures and completions. It is
safe for multiple worker processes on this Linux host; it must not be placed on
SMB/NFS or opened directly by remote workers. The current loopback API is an
operator/control-panel boundary and deliberately has no claim or run endpoint.
A separate worker-only API authenticates each named worker by a SHA-256 token
digest, authorizes its typed pool, and exposes only claim, renew, stage, fail,
artifact-upload and completion operations. Remote workers therefore never open
SQLite and never submit a command string.

Retryable failures are returned to the ordered queue with a durable exponential
backoff. `retry_backoff_seconds` supplies the initial delay and
`retry_backoff_max_seconds` caps it; the next eligible time is persisted in the
ledger, so restarting or adding workers cannot turn a failing cell into a tight
retry loop. Terminal failures are assigned a normalized stage/error class.
`authority_failure_threshold` opens a durable circuit breaker after that many
failures in one authority-resolution class within the active batch. The breaker
pauses new claims without cancelling leases already in flight; an operator must
inspect the appended `queue.circuit-opened` event before resuming.

The same queue document owns the unattended operating envelope. `[schedule]`
defines an IANA-timezone admission window. The reviewed default is
`00:00–05:30 Europe/Luxembourg`: ordered short chunks are admitted one at a time
during the window, and `finish_started_batch = true` lets a chunk drain after
05:30 without admitting the next batch. The durable admission survives worker
restarts. `[resources]` gates every new lease on available Linux memory,
project-filesystem space, load per logical CPU and the highest detected thermal
zone, including leases claimed while a started batch drains. `[notifications]`
writes typed failure, retry, drain and resource-block events to an ignored,
fsynced JSONL outbox; an optional HTTPS webhook is resolved only from named
worker environment variables. Notification delivery failure is reported but
cannot alter a lease transition. Inspect the live decision without creating or
claiming a job with `fidb-poc queue preflight` or `GET /api/v1/preflight`.

Manually admit exactly the next ordered batch without waiting for the clock:

```sh
uv run fidb-poc queue start-block --project-root .
```

This explicit timer bypass still requires `armed = true`; it records the block
admission but does not itself execute a cell. Running local or remote workers
consume only that admitted batch until it drains.

Start the bounded API on `reference-host` without exposing SQLite or a coordinator
port over Tailscale:

```sh
uv run fidb-poc api serve --bind 127.0.0.1 --port 8765
```

The control panel's same-origin `/api/fidb/*` route runs server-side on
`reference-host` and forwards only a fixed route set to that loopback API. Read
routes expose the ledger, timings, detected capabilities and one validated
projection of recipes, targets, native routes, treatments, toolchains,
sensitivity factors, variants and plans. `targets/registry.toml` keeps every
reviewed, study-observed or planned platform/ABI visible independently of
whether this host has a compiler. Android now has eight qualified Linux-hosted
NDK routes: four ABIs across r27d/Clang 18 and r29/Clang 21 at API 21. These
routes are visible and runnable but do not queue work by themselves. The
**Targets & toolchains** view overlays that managed lifecycle, installed native
tools and checksum-cached registry inputs without confusing an
archive-only libc candidate with a source-build compiler. The matrix therefore
does not maintain a second hard-coded build catalog. Its `built` markers use
the sealed inventory from that projection.

The **Matrix** page is operationally ordered: sealed builds and their achieved
route/treatment width; active queue batches in exact TOML order; reviewed
recipes that are buildable but unscheduled; ranked families missing recipes;
and target/compiler requirements missing executable toolchains. Declared
possibility is never presented as built or scheduled. The denominator study,
applicability laboratory and full cell crosspoint are collapsed drill-downs by
default so the queue and its actionable gaps remain readable at a glance. The
control panel requests a bounded, compact snapshot projection for display;
the complete attempts, timing payloads and job authorities remain in the
SQLite ledger and evidence files.

The panel can submit its generated TOML to a resolve-only endpoint, then save a
successfully resolved request under `plans/drafts/`. Updates use the previous
TOML hash and fail on a conflict rather than silently overwriting another edit.
The saved document is still only plan intent: it is not inserted into the
priority queue and no build starts. Thus a Mac browser may use the
Tailscale-served control panel without treating the Mac's own `localhost` as
the execution host. The API cannot arm a queue, claim a job, accept a command,
or start a build.

The remote-worker API is a separate process and port. It binds to loopback only;
publish it to another machine only through a reviewed HTTPS reverse proxy. A
remote client requires HTTPS, re-resolves the frozen cell against its local
reviewed checkout, keeps the lease alive while executing, uploads the
seal/FIDB/FIDBF with digests, and asks the host to publish. The host rechecks
lease ownership, resolved cell identity, seal contents, artifact sizes/digests
and timing before fenced completion. Worker tokens live only in mode-0600
environment/credential files; TOML and SQLite contain no plaintext token.
The `macos-native` pool additionally requires a reviewed external-toolchain
preflight registration. The Mac uploads only the three sealed outputs; Xcode,
the SDK, Apple credentials, source/build scratch, and signing material remain
on the Mac. The Linux coordinator validates and atomically publishes accepted
outputs under `artifacts/runs/`, after which the ordinary GUI evidence view
uses the same SQLite result references as Linux attempts.
Large outputs use idempotent 8 MiB chunks and receive a final whole-file
SHA-256 check before publication; the default per-artifact ceiling is 4 GiB.

## Experimental lane databases

The repository now contains an additive lane-database experiment. A broad lane
is the analyst-facing device/platform-family pack (`linux-x86`, `windows-x86`,
`android-arm`, and so on); exact format, ISA, bitness, endianness, OS/ABI,
Ghidra language/compiler specification and FID policy remain internal
query-compatible sublanes selected from inspected program facts. Compiler
version, treatment, library and release remain provenance rather than forcing a
user-visible database choice.

The current implementation can validate the registry, preview a measured width
run and explicitly build a new immutable **raw** SQLite generation containing
every observation. It does not deduplicate by default, does not modify source
evidence and does not activate a native Ghidra database. Deduplication is an
independent, dry-run-by-default Python experiment. Native projection and
operational admission remain gated on relationship-complete worker evidence,
query-equivalence testing and held-out ecological false-positive validation.

See [`LANE_DATABASES.md`](LANE_DATABASES.md) for the exact model, commands,
deduplication key, current limitations and rollback procedure. The Targets &
toolchains GUI projects the same registry and deliberately reports zero active
packs.

Every worker uses a fixed typed dispatcher and re-resolves the reviewed recipe,
pins, target, toolchain, adapter and executor before running. A terminal success
requires preparation/build, artifact validation, Ghidra analysis, FID
population, non-empty FIDB and FIDBF export, and an atomic provenance seal.
Successful attempts are published under `artifacts/runs/`; incomplete attempts
cannot become completed ledger entries. No queue or plan field accepts a raw
command.

[`plans/archive-uclibc-powerpc.toml`](plans/archive-uclibc-powerpc.toml)
demonstrates the archive route as ordinary plan authority. The registry supplies
the URL, digest, static-library member and reviewed object allowlist; the plan
supplies only the library and registry identities. This is extraction and Ghidra
analysis, not cross-compilation.

Each `library-local` attempt now records durable, fenced stage spans for request and authority
validation, pinned source/toolchain acquisition and verification, extraction,
patch/configure/compile, archive-object selection, artifact validation, Ghidra
startup and import/analysis, FID population and validation, FIDB/FIDBF export,
provenance sealing, and publication. Workers measure duration with a monotonic
clock and retain UTC boundaries, cache/byte/object/program/function counts where
available, process/child CPU time, peak RSS, skips, failures, retries, and
interruptions. The sealed cell result carries its execution-timing document;
the SQLite ledger remains the durable cross-attempt history.

Malware is not part of this worker pool. Its existing typed build path remains
available separately, but its download/extract/build internals are not yet
split into the same fine-grained stage taxonomy.

QEMU is outside the active `library-local` pool, but its default source-build
route retains a distinct `executor-image-acquire` span for the pinned VM ISO so
that ISO/cache time cannot contaminate source or cross-toolchain distributions.

Read the aggregate timing evidence at `GET /api/v1/timings` or through the
control panel's same-origin `GET /api/fidb/timings`. Stage p50/p90 values use
only completed worker-monotonic spans. Coordinator wall-clock interruptions and
queue waits remain visible with their source and basis, but are excluded from
those stage distributions. The successful-attempt service-rate proxy is absent
until a complete workflow has been observed; it excludes retry work, queue/idle
time and worker concurrency, so it is not presented as measured whole-factory
throughput. ETA remains absent until a matching evidence-backed model
has enough samples; the UI reports **Collecting evidence** instead of inventing
a rate from cell counts.

The repository includes inactive user-service templates for the
[`loopback API`](operations/fidb-coordinator-api.service) and
[`library-local workers`](operations/fidb-library-local-worker@.service), plus
the [`Tailscale control panel`](operations/fidb-control-panel.service).
They are not installed, enabled or started by the repository, and a worker
refuses to start while the TOML queue is disarmed. See
[`operations/README.md`](operations/README.md) for the deliberately manual
activation and resource-review procedure.

A real run creates temporary working state and evidence:

```text
work/                         downloaded/extracted source, builds, logs, Ghidra projects
artifacts/libs/fidb/                  generated per-cell FIDBs
artifacts/libs/fidb_manifest.csv      result and provenance rows
```

`--fresh` removes `work/` and `artifacts/libs/` at the start and then recreates
them during the run (`artifacts/malware/` and `artifacts/fidbs/` are a separate
subsystem's evidence and are never touched by this build's `--fresh`). It is a
clean-build option, not a post-run cleanup option.

Without `--fresh`, only a hash-verified downloaded source archive may be reused.
Every real run still replaces the worker-managed extracted sources, builds, logs,
Ghidra state, current FIDBs and manifest. Paths outside those managed locations
are not part of the cleanup.

Durable queue attempts use the separate post-run retention system documented in
[`RETENTION.md`](RETENTION.md). Its TOML policy always produces a verified,
content-addressed dry-run before deletion. Successful attempts remain whole
until a relationship-complete lane-import receipt exists; failed attempts are
reduced only after concise evidence is bundled, with unlike retries and holds
preserved. A terminal queue also recycles long-lived Ghidra workers once so JVM
heap is returned to the OS, even when the final block drains after the claim
window closes. Each fresh worker records a secondary RSS/JVM audit. The control
panel exposes planning, exact apply, protected evidence, quarantine and memory
verification under **Operations → Retention**. Recycled workers with no durable
pending work park before full queue resolution and wake through a lightweight
TOML-controlled ledger check.

These directories are intentionally ignored and are not source deliverables. A
source-only handoff must omit `work/`, `artifacts/libs/`, `.venv/`, `.idea/`,
Python caches and notebook execution outputs. Prefer producing a handoff from a
real clean Git checkout or an explicit source allowlist rather than archiving
an active working directory. At minimum, remove the generated roots after
preserving any evidence that is meant to be reviewed:

```sh
rm -rf -- work artifacts/libs
```

The manifest and FIDBs are evidence for a particular execution, not permanent
proof embedded in the source distribution. Share them separately when execution
evidence is required.

## Safety and authority boundary

The worker resolves a library name through a deterministic catalogue, verifies the
downloaded bytes, selects a fixed adapter, validates the compiler and output
formats, and asks Ghidra to populate the FIDB. Unknown names, hash mismatches,
missing markers, wrong compiler identities, wrong binary formats, population-count
mismatches and empty FIDBs fail closed.

An approved source archive still contains executable upstream build logic such as
`configure` and Makefiles. A SHA-256 check establishes which bytes were run; it
does not make those bytes safe. This PoC assumes reviewed pinned upstreams, a
controlled environment without unreviewed compiler/linker overrides, and a
least-privileged non-sensitive host.

Production hardening is explicitly deferred. This PoC does not claim:

- sandboxed hostile-source execution;
- support for additional operating systems, architectures, compilers or projects;
- byte-for-byte reproducibility across independent hosts;
- signed releases, SBOM/SPDX output or an external authority database;
- a standalone installable worker package;
- continuous Ghidra integration in hosted CI; or
- production publication, retention or merged route-pack workflows.

This source snapshot does not contain a project `LICENSE` file or license
metadata. Do not treat access to the files as permission to redistribute them;
an external handoff needs owner-approved terms or a confirmed governing private
agreement.

## Requests without recipes

If a requested library has no approved recipe, the worker fails closed and records
the request in `recipe_requests/pending.csv`. This file is a human-review queue,
not an executable recipe. For example:

```sh
uv run fidb-poc \
  --plan \
  --library libpng \
  --route linux-x86_64-gnu-gcc \
  --request-priority 1
```

Priorities are `0` for a campaign or analyst request, `1` for a ranked catalogue
and `2` for discovery. Adding a recipe or adapter is an ordinary reviewed source
change.

## Hunting an unknown target

Building the two reviewed recipes above is only one thing `fidb-poc` does.
The same binary also takes an arbitrary target and works out which libc it was
probably built against, cross-compiling source candidates through the default
isolated, network-severed QEMU executor when no prebuilt archive matches -- via the
`inspect`/`investigate`/`hunt`/`build-malware`/`hunt-doctor` subcommands
(`fidb-hunt` still works too, as a thin alias over the same code):

```text
target binary
  -> investigate: infer machine/endianness/elf_class and libc family hypotheses
  -> select: matching toolchain rows + recipe-generated cells, closest priority first
  -> prepare: extract a prebuilt libc.a, or cross-compile one through the selected executor
  -> match: Ghidra FID comparison against the target
  -> report + copy: exported .fidb/.fidbf per unambiguous match, ready to reuse
```

```sh
uv run fidb-poc hunt path/to/target --fidb-dir artifacts/fidbs
```

Source-mode cells accept `--executor {qemu,local}` on `hunt` and
`build-malware`. `qemu` is the default. `--executor local` is an explicit
opt-in that runs the same pinned cross-toolchain, reviewed named adapter and
target flags directly in the invoking Linux environment (including a
Toolbx/Distrobox), without the QEMU isolation boundary. Executor choice is
recorded as route provenance and does not change FID treatment. Archive-only
hunt candidates and the native zlib/bzip2 worker are unaffected.

Candidates come from `toolchains/registry.toml` (pinned cross-toolchains,
some directly archive-extractable) and `recipes/libs/*.toml`
(`mode="source"`, fanned out per matching toolchain by
`recipe_generator.generate_cells`) -- see `UNIFICATION_PLAN.md` for why this
is one schema instead of the two ad hoc ones this repository started with.

The same executor routing also builds a static, known-source malware corpus from
`recipes/malware/*.toml`, for use as ground truth rather than as an unknown
target to match:

```sh
uv run fidb-poc build-malware --recipes recipes/malware
```

See `recipes/malware/README.md` before adding a fork recipe. Source archives
are pinned by SHA-256, never a moving branch ref; use the default QEMU executor
when its disposable offline boundary is required.

## Verification

The deterministic unit and formatting checks do not download library source or run
Ghidra:

```sh
uv run python -m unittest discover -s tests -v
uv run black --check src tests ghidra_scripts
```

GitHub Actions runs those checks on Python 3.14 only; it does not run Ghidra. The
actual supported demonstration is the explicit host command in **Run the
demonstration**. An opt-in live zlib check is also available when the host has
network access, the native toolchain and Ghidra:

```sh
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
FIDB_RUN_LIVE_SMOKE=1 \
  uv run python -m unittest tests.test_live_smoke -v
```

## Code map

| Path | Responsibility |
| ---- | -------------- |
| `src/fidb_poc/cli.py` | `fidb-poc` command-line boundary and exit status |
| `src/fidb_poc/config.py` | recipe, route and treatment validation |
| `src/fidb_poc/adapters.py` | fixed Autoconf/Make command construction |
| `src/fidb_poc/pipeline.py` | retrieval, build isolation, validation, Ghidra and manifest output |
| `ghidra_scripts/populate_library_fid_databases.py` | FID database population adapter |
| `recipes/*.toml`, `recipes/README.md` | reviewed name-to-source catalogue, fixed-adapter map and qualification boundary |
| `src/fidb_poc/hunt_cli.py` | hunt/malware subcommand boundary (`hunt`, `build-malware`, `doctor`, `investigate`, `inspect`), reached via `fidb-poc <subcommand>` or the `fidb-hunt` alias |
| `src/fidb_poc/hunt.py` | investigate -> select -> prepare -> match -> export workflow |
| `src/fidb_poc/toolchain_registry.py` | pinned cross-toolchain rows (`toolchains/registry.toml`) |
| `src/fidb_poc/toolchain_cache.py` | locked, checksum-verified content-addressed acquisition |
| `src/fidb_poc/source_packs.py`, `sources/*.toml` | source-only release packs, cache status and sequential verified acquisition |
| `src/fidb_poc/width_batch.py`, `batches/*.toml` | immutable source-to-width batch bindings, exact cardinality and recipe readiness |
| `src/fidb_poc/toolchain_prepare.py`, `toolchain_inputs.py` | safe prepared roots and private non-redistributed input binding |
| `src/fidb_poc/toolchain_qualification.py` | reviewed route composition boundary and fixed target/language smoke qualification |
| `src/fidb_poc/external_workers.py` | command-free external definitions, native preflight, and registration validation |
| `src/fidb_poc/toolchain_packs.py` | strict pack/input/route/qualification/profile authority and read-only lifecycle resolution |
| `src/fidb_poc/toolchain_cli.py` | typed registry acquisition and profile lifecycle commands |
| `toolchains/packs.toml`, `inputs.toml`, `routes.toml`, `qualifications.toml`, `profiles/` | portable Linux x86-64 acquisition and qualification authority |
| `lanes/registry.toml`, `src/fidb_poc/lane_registry.py` | experimental broad-lane/exact-sublane authority and conservative resolver |
| `src/fidb_poc/lane_database.py`, `lane_compiler.py` | immutable raw occurrence store and preview-first width-evidence compiler |
| `scripts/deduplicate_lane_db.py` | standalone inspectable, dry-run-by-default compact-copy experiment |
| `src/fidb_poc/recipe_generator.py` | recipe x toolchain registry -> resolved build cells |
| `src/fidb_poc/libc_catalog.py` | cell selection, download, extraction and VM-isolated source build |
| `src/fidb_poc/malware_build.py` | cell -> linked malware binary + provenance manifest |

The repository also contains an experimental `fidb-language-probe` analysis
utility. It is not part of the supported worker demonstration or the validation
claim above.

[1]: https://docs.astral.sh/uv/
