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

With no `--library`, the worker uses the name-only request queue in `worker.json`
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

`worker.json` is trusted operator configuration for the single Linux route, one
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
list. Each batch points to a reviewed `fidb-plan/v1` document. The queue ships
with `armed = false`, so inspection and synchronization cannot start a build.

Synchronize and inspect its durable state without executing anything:

```sh
uv run fidb-poc queue sync
uv run fidb-poc queue status --full
```

After an operator deliberately changes `armed` to `true`, one or more workers
can consume it continuously:

```sh
uv run fidb-poc queue run --pool library-local --worker-id reference-host-1
uv run fidb-poc queue run --pool library-local --worker-id reference-host-2
```

The active queue is deliberately library-only: native cells and source-library
cells with the explicit `local` executor. The typed `library-local` worker pool
fails closed against QEMU and malware cells even if a later queue edit places
one before an eligible library cell. `max_workers = 2` is the initial active
lease cap for this 16-core/32-thread host; raise it only after the ledger has
representative build and Ghidra memory/timing evidence. A worker may invoke
four compiler jobs and one Ghidra JVM, so hardware-thread count is not a safe
worker count.

TOML remains the source of requested coverage and priority. The ignored local
SQLite ledger at `var/fidb-coordinator/ledger.sqlite3` records only runtime
state: claims, fenced leases, attempts, stages, failures and completions. It is
safe for multiple worker processes on this Linux host; it must not be placed on
SMB/NFS or opened directly by remote workers. The current loopback API is an
operator/control-panel boundary and deliberately has no claim or run endpoint;
remote workers still require a later authenticated worker API.

Start the bounded API on `reference-host` without exposing SQLite or a coordinator
port over Tailscale:

```sh
uv run fidb-poc api serve --bind 127.0.0.1 --port 8765
```

The control panel's same-origin `/api/fidb/*` route runs server-side on
`reference-host` and forwards only a fixed route set to that loopback API. Read
routes expose the ledger, timings, detected capabilities and one validated
projection of recipes, native routes, treatments, toolchains, sensitivity
factors, variants and plans. The matrix therefore does not maintain a second
hard-coded build catalog. Its `built` markers use the sealed inventory from
that projection.

The panel can submit its generated TOML to a resolve-only endpoint, then save a
successfully resolved request under `plans/drafts/`. Updates use the previous
TOML hash and fail on a conflict rather than silently overwriting another edit.
The saved document is still only plan intent: it is not inserted into the
priority queue and no build starts. Thus a Mac browser may use the
Tailscale-served control panel without treating the Mac's own `localhost` as
the execution host. The API cannot arm a queue, claim a job, accept a command,
or start a build.

Every worker uses a fixed typed dispatcher and re-resolves the reviewed recipe,
pins, target, toolchain, adapter and executor before running. A terminal success
requires preparation/build, artifact validation, Ghidra analysis, FID
population, non-empty FIDB and FIDBF export, and an atomic provenance seal.
Successful attempts are published under `artifacts/runs/`; incomplete attempts
cannot become completed ledger entries. No queue or plan field accepts a raw
command.

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
| `recipes/*.toml` | reviewed name-to-source catalogue, one `fidb-recipe/v3` schema throughout |
| `src/fidb_poc/hunt_cli.py` | hunt/malware subcommand boundary (`hunt`, `build-malware`, `doctor`, `investigate`, `inspect`), reached via `fidb-poc <subcommand>` or the `fidb-hunt` alias |
| `src/fidb_poc/hunt.py` | investigate -> select -> prepare -> match -> export workflow |
| `src/fidb_poc/toolchain_registry.py` | pinned cross-toolchain rows (`toolchains/registry.toml`) |
| `src/fidb_poc/recipe_generator.py` | recipe x toolchain registry -> resolved build cells |
| `src/fidb_poc/libc_catalog.py` | cell selection, download, extraction and VM-isolated source build |
| `src/fidb_poc/malware_build.py` | cell -> linked malware binary + provenance manifest |

The repository also contains an experimental `fidb-language-probe` analysis
utility. It is not part of the supported worker demonstration or the validation
claim above.

[1]: https://docs.astral.sh/uv/
