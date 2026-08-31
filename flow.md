# FIDB worker flow

This document traces a normal build from the `fidb-poc` CLI command to the
generated Function ID databases and provenance manifest.

The current `worker.toml` expands to two build cells:

```text
zlib x linux-x86_64-gnu-gcc x baseline_o2
> one zlib FIDB

bzip2 x linux-x86_64-gnu-gcc x baseline_o2
> one bzip2 FIDB
```

## End-to-end flow

```text
CLI command
> Python entry point
> Parse and validate arguments
> Load worker configuration
> Resolve reviewed library recipes
> Select routes and treatments
> Prepare work and output directories
> Download and hash-check source archives
> Safely extract source trees
> Detect source identity and build system
> Expand library x route x treatment build cells
> Compile a static library for each cell
> Extract and validate compiled object files
> Import objects into Ghidra
> Generate one candidate FIDB per library
> Validate Ghidra's population report
> Admit valid FIDBs into artifacts/libs/fidb/
> Write artifacts/libs/fidb_manifest.csv
> Return success only if every requested cell completed
```

## 1. CLI entry

Example invocation:

```bash
GHIDRA_HEADLESS=/opt/ghidra/support/analyzeHeadless \
uv run fidb-poc \
  --library zlib \
  --route linux-x86_64-gnu-gcc \
  --profile smoke
```

Inside Toolbx, use
`GHIDRA_HEADLESS=/run/host/opt/ghidra/support/analyzeHeadless` instead. If Java
discovery requires it there, also set
`JDK_JAVA_OPTIONS=-XX:-UseContainerSupport`.

```text
uv run fidb-poc
> pyproject.toml resolves the command to fidb_poc.cli:main
> cli.parser() parses the arguments
> cli.main() controls the requested operation
```

Code:

- [`pyproject.toml`: CLI registration](pyproject.toml)
- [`parser()`](src/fidb_poc/cli.py)
- [`main()`](src/fidb_poc/cli.py)

The main CLI branches are:

```text
--doctor
> inspect the selected toolchain without building

--plan
> print the expanded build cells without downloading or compiling

normal build
> require at least one explicit --route
> validate the checkout
> optionally perform safe --fresh cleanup
> call pipeline.execute()
```

Code: [`cli.main()` dispatch](src/fidb_poc/cli.py)

### Declarative planning path

The visual planner and automation use the same request boundary:

```text
plans/*.toml
> validate reviewed recipe, route, treatment, toolchain and factor identities
> expand base cells and the named factor cross-product
> retain unavailable desired cells as explicit blockers
> snapshot sensitivity and usefulness context
> digest the static resolved request
> accept built state only from a valid cell seal plus matching FIDB/FIDBF
> show loose unsealed FIDBs separately without changing the plan digest
> write resolved JSON for inspection or later coordinator dispatch
```

Run this read-only resolution with `fidb-poc resolve-plan`. The backend also
projects every reviewed recipe, native route, treatment, toolchain, factor,
variant and plan through one read-only catalog endpoint. The GUI renders that
projection rather than maintaining its own build catalog. Its generated TOML
can be resolved through the same resolver and, only after successful
resolution, atomically saved under `plans/drafts` with a compare-and-swap file
hash. Saving remains non-executing and does not insert the draft into a queue.
TOML and the CLI-resolved document remain the authority. `qemu` versus `local`
is source-build routing and provenance, not a FID treatment. This path does not
alter the existing native build dispatch.

### Priority queue and complete-cell dispatch

```text
plans/priority-queue.toml
> order batches by explicit batch_order
> resolve and freeze each referenced fidb-plan/v1 request
> persist planned and blocked entries in the local SQLite ledger
> claim the first runnable entry with a fenced, renewable lease
> create one isolated attempt root
> re-resolve its reviewed recipe, pins, toolchain, adapter and executor
> prepare and build/archive the analysis inputs
> validate the target artifacts
> ingest and analyze them in isolated Ghidra state
> populate and validate the FID database
> export both FIDB and FIDBF
> atomically seal provenance, publish the attempt and mark it complete
> continue to the next runnable entry
```

Pinned cross-toolchain and archive-candidate payloads pass through a shared
managed boundary before per-attempt preparation:

```text
reviewed registry identity
> resolve fixed URL + SHA-256 from toolchains/registry.toml
> lock var/fidb-toolchains/locks/<sha256>.lock
> reuse only a verified var/fidb-toolchains/downloads/<sha256> entry
> otherwise download with bounded timeout/retries and a byte limit
> stream SHA-256; quarantine invalid old bytes; fsync + atomic rename
> unlock, then extract/build only inside the isolated attempt root
```

`targets/registry.toml` is the independent coverage inventory above this
execution path. It records reviewed Linux ABI shapes, study-observed platform
gaps and viewer-only Android coverage intent even when no route exists; live
capability detection overlays installed, checksum-cached, missing and
archive-only states.

The CLI exposes status/acquisition by registry identity only. It has no URL,
hash, command or compiler override.

Every library-local execution step above is represented by a durable stage
attempt. The worker emits UTC start/finish boundaries and monotonic durations
for:

```text
request-validation -> authority-resolution
source-acquire / toolchain-acquire -> input-verification
executor-image-acquire (QEMU route only)
source-extract / toolchain-extract -> patch -> configure -> compile
archive-object-selection -> artifact-validation
ghidra-startup -> ghidra-import-analysis -> fid-population -> fid-validation
fidb-export -> fidbf-export -> provenance-seal -> publication
```

Stages that do not apply to a route are explicitly `skipped`; failures retain
their measured duration and error type. Lease expiry closes an open span as a
coordinator-wall-clock `interrupted` observation so it remains auditable but is
not mixed into worker-monotonic performance percentiles. Stage metrics include
cache state, bytes and produced-object/program/function counts where the stage
can report them, plus process/child CPU and peak RSS readings for capacity
review. The result seal embeds the worker timing document, while the ledger
adds fenced publication and cross-attempt history.

`fidb-poc queue sync` and `queue status` are non-executing. `queue run` consumes
the list only when the TOML has `armed = true`; pause stops new claims without
invalidating work already leased. Multiple local worker processes coordinate
through transactional SQLite leases, while each attempt has independent work,
Ghidra and artifact paths. Blocked entries stay visible and do not prevent later
runnable entries from progressing. Retryable failures receive a persisted,
exponentially increasing next-eligible time capped by the queue's reviewed TOML
policy; other workers cannot bypass that delay. The current `library-local`
worker pool atomically skips every cell except native libraries, source libraries
routed through the explicit `local` executor, and archive libraries routed
through the fixed `archive-local` extractor; it never claims QEMU or malware
work.

Before each claim, the worker evaluates the queue's timezone-aware schedule and
live host gates. New claims stop at the configured morning boundary; a timer
returns an over-running attempt to the fenced queue at hard cutoff. Memory,
filesystem, normalized load and thermal failures prevent a claim without
consuming an attempt. Typed operational events are appended to the durable
notification outbox, with optional HTTPS delivery isolated from queue state.

The analyst/control path is deliberately separate from worker execution:

```text
Mac browser over Tailscale
> control-panel same-origin /api/fidb/* route on reference-host
> fixed server-side proxy to 127.0.0.1:8765
> bounded local coordinator API
> host-local SQLite ledger and read-only capability detection
```

The local API exposes health, status, snapshot, events, capabilities, the
authoritative catalog and bounded timing history, plus typed
sync/pause/resume and validated plan-draft resolve/save operations. The Timing
workspace shows active clocks, retries/failures, measured distributions and
throughput; it displays no ETA until the API has a defensible sample-backed
model. The API cannot arm, claim or run a cell. Remote workers use a separate
loopback worker API published only through reviewed HTTPS. A named credential
authorizes a typed pool; the worker receives a fenced lease, streams stage
transitions, and uploads only its seal, FIDB and FIDBF. The host binds those
files and timing back to the leased resolved cell before durable publication.
Remote workers never access SQLite or submit raw commands.

## 2. Configuration and recipe resolution

```text
cli.main()
> load_configuration(worker.toml)
> _resolve_requests()
> _recipe_catalog()
> _load_recipe(recipes/*.toml)
> select_configuration()
```

Code:

- [`load_configuration()`](src/fidb_poc/config.py)
- [`_resolve_requests()`](src/fidb_poc/config.py)
- [`_load_recipe()`](src/fidb_poc/config.py)
- [`select_configuration()`](src/fidb_poc/config.py)

The trusted worker configuration currently selects:

```text
worker.toml
> requested libraries: zlib and bzip2
> route: linux-x86_64-gnu-gcc
> compiler: /usr/bin/gcc
> output format: x86-64 ELF
> Ghidra language: x86:LE:64:default
> Ghidra compiler specification: gcc
> treatment: baseline_o2
```

Configuration: [`worker.toml`](worker.toml)

Library resolution is name-based:

```text
zlib
> recipes/zlib.toml
> version 1.3.1
> pinned source URL and SHA-256
> expected source markers
> Autoconf adapter
> expected libz.a

bzip2
> recipes/bzip2.toml
> version 1.0.7
> pinned source URL and SHA-256
> expected source markers
> Make adapter
> expected libbz2.a
```

Recipes:

- [`recipes/zlib.toml`](recipes/zlib.toml)
- [`recipes/bzip2.toml`](recipes/bzip2.toml)

An unknown name takes a fail-closed side path:

```text
unknown --library value
> RecipesNotFoundError
> record_missing_requests()
> recipe_requests/pending.csv
> exit without downloading or executing unreviewed build instructions
```

Code:

- [`RecipesNotFoundError` handling](src/fidb_poc/cli.py)
- [`record_missing_requests()`](src/fidb_poc/request_queue.py)

## 3. Pipeline setup

```text
cli.main()
> _validate_project_checkout()
> optional safe --fresh cleanup
> execute(configuration, project_root)
```

Code:

- [`_validate_project_checkout()`](src/fidb_poc/cli.py)
- [`execute()` invocation](src/fidb_poc/cli.py)
- [`pipeline.execute()`](src/fidb_poc/pipeline.py)

`execute()` validates and prepares these generated paths:

```text
PROJECT/
> work/
  > downloads/
  > sources/
  > builds/
  > logs/
  > ghidra/
> artifacts/libs/
  > fidb/
  > fidb_manifest.csv
```

Code: [`execute()` directory setup](src/fidb_poc/pipeline.py)

`work/downloads/` is a verified download cache. The other generated working
directories and the output FIDB directory are recreated for the invocation.

## 4. Download and verify source

For each resolved library:

```text
execute()
> download_library()
> download the recipe's pinned URL to a partial file
> calculate SHA-256
> compare it with the recipe SHA-256
> atomically rename the verified download into the cache
```

Code: [`download_library()`](src/fidb_poc/pipeline.py)

Generated cache entries:

```text
work/downloads/
> zlib-1.3.1.tar.gz
> bzip2-1.0.7.tar.gz
```

Failure path:

```text
downloaded archive has an unexpected SHA-256
> delete the partial archive
> raise PipelineError
> do not compile it
```

## 5. Safely extract source

```text
verified archive
> extract_source()
> verify the archive hash again
> inspect every archive member
> reject links, devices, traversal and unsupported member types
> extract into a temporary staging directory
> require the recipe's expected source directory
> move the staged tree into work/sources/
```

Code: [`extract_source()`](src/fidb_poc/pipeline.py)

Generated source roots:

```text
work/sources/zlib-1.3.1/zlib-1.3.1/
work/sources/bzip2-1.0.7/bzip2-1.0.7/
```

## 6. Detect source identity and build system

```text
extracted source
> detect_project()
> require the recipe's project markers
> detect known build-system markers
> reject unexpected build systems
> detect supported source languages
```

Code: [`detect_project()`](src/fidb_poc/adapters.py)

Current detection:

```text
zlib source
> zlib.h + configure
> Autoconf adapter

bzip2 source
> bzlib.h + Makefile
> Make adapter
```

## 7. Expand build cells

```text
every selected library
> every selected route
> every selected treatment
> one build_library() call per combination
```

Code: [`execute()` build loops](src/fidb_poc/pipeline.py)

The key for each record is:

```text
(library identifier, route ID, treatment ID)
```

## 8. Compile each cell

```text
build_library()
> copy pristine source into the cell build directory
> create a restricted deterministic environment
> identify and validate the configured compiler
> locate archiver and ranlib
> build_commands()
> execute fixed adapter commands
> find the exact expected static archive
```

Code:

- [`build_library()`](src/fidb_poc/pipeline.py)
- [`compiler_identity()`](src/fidb_poc/pipeline.py)
- [`build_commands()`](src/fidb_poc/adapters.py)
- [`find_static_archives()`](src/fidb_poc/adapters.py)
- [`run_command()` and log capture](src/fidb_poc/pipeline.py)

The fixed adapters produce commands shaped like:

```text
zlib
> sh configure --static
> make -j4 libz.a AR=/usr/bin/ar ARFLAGS=rc RANLIB=/usr/bin/ranlib

bzip2
> make -j4 libbz2.a CC=/usr/bin/gcc CFLAGS=<trusted flags> AR=/usr/bin/ar RANLIB=/usr/bin/ranlib
```

The recipe cannot supply a command. Command construction lives in
`src/fidb_poc/adapters.py` and is ordinary reviewed code.

Generated build material and logs:

```text
work/builds/<library>-<route>-<treatment>/
work/logs/build/
```

## 9. Extract and validate object files

The baseline compile-phase treatment analyzes the members of each static
archive individually:

```text
libz.a or libbz2.a
> archiver t
> reject duplicate, nested or non-object members
> archiver x
> reconcile listed members with extracted files
> file --brief each object
> require the route's ELF + x86-64 + relocatable markers
```

Code:

- [`_extract_archive_objects()`](src/fidb_poc/pipeline.py)
- [`_validate_objects()`](src/fidb_poc/pipeline.py)

Generated objects:

```text
work/builds/<cell>/objects/
> adler32.o
> crc32.o
> compress.o
> ...
```

After this stage the cell's `BuildRecord.status` becomes `built`. A failed cell
is retained in the manifest as `build_failed` with its error message.

## 10. Import compiled objects into Ghidra

```text
execute()
> populate_fidbs()
> _populate_group() for each route/treatment group
> locate analyzeHeadless and pyghidraRun
> identify Ghidra, Java and PyGhidra versions
> copy cell objects into Ghidra reference folders
> invoke analyzeHeadless
```

Code:

- [`populate_fidbs()`](src/fidb_poc/pipeline.py)
- [`_populate_group()`](src/fidb_poc/pipeline.py)
- [`find_ghidra()`](src/fidb_poc/pipeline.py)
- [`ghidra_environment()`](src/fidb_poc/pipeline.py)

The first Ghidra invocation is constructed as:

```text
analyzeHeadless
> import work/ghidra/references/ recursively
> use processor x86:LE:64:default
> use compiler specification gcc
> run FunctionIDHeadlessPrescript.java
> store analyzed programs in a temporary Ghidra project
```

Code: [`analyzeHeadless` argument construction](src/fidb_poc/pipeline.py)

Generated Ghidra working data:

```text
work/ghidra/projects/
work/ghidra/references/
work/ghidra/user/
work/logs/ghidra/<route>-<treatment>-import.log
```

## 11. Populate candidate FID databases

```text
_populate_group()
> write <route>-<treatment>-libraries.tsv
> invoke pyghidraRun --headless
> run populate_library_fid_databases.py as a post-script
> find imported Ghidra programs
> create one candidate FIDB per library
> generate Function ID signatures
> write a JSONL population report
```

Code:

- [`pyghidraRun` argument construction](src/fidb_poc/pipeline.py)
- [`populate_library_fid_databases.py`](ghidra_scripts/populate_library_fid_databases.py)

Inside the Ghidra script:

```text
libraries.tsv row
> find the corresponding Ghidra project folder
> collect analyzed programs
> FidFileManager.createNewFidDatabase()
> FidService.createNewLibraryFromPrograms()
> save the candidate FIDB
> report program, attempted, added and excluded counts
```

Candidate location:

```text
work/ghidra/candidates/linux-x86_64-gnu-gcc-baseline_o2/
> zlib-1.3.1-linux-x86_64-gnu-gcc-baseline_o2.fidb
> bzip2-1.0.7-linux-x86_64-gnu-gcc-baseline_o2.fidb
```

## 12. Validate and admit FIDBs

```text
population JSONL
> _read_population_report()
> _validate_population_report()
> verify library, version and variant
> verify the expected FIDB path
> verify the submitted program count
> require attempted = added + excluded
> require at least one added signature
> require a non-empty FIDB
> move the candidate into artifacts/libs/fidb/
> hash the final FIDB
> mark the BuildRecord complete
```

Code:

- [`_read_population_report()`](src/fidb_poc/pipeline.py)
- [`_validate_population_report()`](src/fidb_poc/pipeline.py)
- [Candidate admission and record update](src/fidb_poc/pipeline.py)

Final database paths:

```text
artifacts/libs/fidb/
> zlib-1.3.1-linux-x86_64-gnu-gcc-baseline_o2.fidb
> bzip2-1.0.7-linux-x86_64-gnu-gcc-baseline_o2.fidb
```

A Ghidra-stage error removes partial admitted output for the affected group and
records `fid_failed` rather than silently dropping the cell.

## 13. Write the provenance manifest

```text
all BuildRecord objects
> write_manifest()
> convert records into CSV rows
> write a temporary CSV in artifacts/libs/
> flush and fsync it
> atomically replace artifacts/libs/fidb_manifest.csv
```

Code:

- [`BuildRecord`](src/fidb_poc/pipeline.py)
- [`write_manifest()`](src/fidb_poc/pipeline.py)
- [`execute()` finalization](src/fidb_poc/pipeline.py)

The manifest records:

```text
library and version
> route and treatment
> source URL and SHA-256
> compiler, archiver and ranlib paths, versions and SHA-256 values
> compiler flags
> static archive path and SHA-256
> analyzed artifact paths and SHA-256 values
> Ghidra identity
> Java and PyGhidra identity
> FIDB path, size and SHA-256
> attempted, added and excluded signature counts
> final status and error
```

The manifest is written even when one or more cells fail. After writing it:

```text
every record is complete
> return artifacts/libs/fidb_manifest.csv
> CLI exits 0

one or more records are incomplete
> retain artifacts/libs/fidb_manifest.csv as evidence
> raise PipelineError with per-cell statuses
> CLI exits 1
```

## Source-mode cross-build execution routes

The separate `hunt` and `build-malware` source-cell paths resolve an executor
alongside the pinned source, pinned cross-toolchain, target ABI and reviewed
named build adapter:

```text
source cell (executor=qemu, default)
> run the fixed adapter inside the existing offline QEMU VM

source cell (executor=local, explicit opt-in)
> run the same fixed adapter directly in the invoking Linux environment
> no QEMU isolation boundary

archive hunt candidate
> extract the pinned prebuilt archive; executor selection does not apply
```

Both routes use the command construction in `source_build.py`; recipes and
callers cannot supply raw commands. The executor is recorded in source-cell
reports/manifests as routing provenance, not as a FID treatment. The native
zlib/bzip2 pipeline described above is unchanged.

## Condensed call chain

```text
uv run fidb-poc
> pyproject.toml: fidb_poc.cli:main
> cli.main()
> config.load_configuration()
> config._resolve_requests()
> config._load_recipe()
> config.select_configuration()
> pipeline.execute()
> pipeline.download_library()
> pipeline.extract_source()
> adapters.detect_project()
> pipeline.build_library()
> adapters.build_commands()
> pipeline._extract_archive_objects()
> pipeline._validate_objects()
> pipeline.populate_fidbs()
> pipeline._populate_group()
> Ghidra analyzeHeadless
> Ghidra FunctionIDHeadlessPrescript.java
> PyGhidra pyghidraRun
> ghidra_scripts/populate_library_fid_databases.py
> FidService.createNewLibraryFromPrograms()
> pipeline._validate_population_report()
> artifacts/libs/fidb/*.fidb
> pipeline.write_manifest()
> artifacts/libs/fidb_manifest.csv
```
