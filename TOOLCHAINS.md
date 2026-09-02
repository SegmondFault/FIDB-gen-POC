# FIDB toolchains

FIDB models compiler breadth as reviewed project data. Profiles select target
and compiler routes; TOML pins downloadable packs or declares external native
workers; typed CLIs report and advance lifecycle state; and the GUI projects
the same authority. Nothing installs a compiler globally.

The current experiment is C libraries, with C++ included where an in-scope
library needs it. The worker and artifact protocols are language-neutral:
future languages get their own profiles, route definitions, probe adapters,
and language capabilities without changing the coordinator transport.

## Current top-ten shape

`c-top10-linux` covers ten ordered target requirements with ten route
implementations:

| Route group | Provisioning | Output |
| --- | --- | --- |
| Linux x86-64, ARMv7, AArch64, MIPS BE/LE, PowerPC, SuperH, M68K | 8 checksum-pinned Bootlin GCC packs | ELF |
| Windows x86-64 | checksum-pinned llvm-mingw | PE/COFF |
| macOS ARM64 | native Apple worker defined in `toolchains/external/` | Mach-O |

The nine downloadable archives total 753,465,840 bytes. Their prepared files
measure 3,852,132,920 bytes after safe extraction. Filesystem allocation and
retained packs outside this profile are separate totals. The macOS worker's
Xcode, Ghidra, build scratch, and temporary output are additional host-local
capacity, not part of the Linux pack measurement.

`c-top10-reference` uses the same ten target requirements and adds native MSVC
as a second Windows implementation. Cross-built PE/COFF never claims native
MSVC equivalence. The macOS route is deliberately native Apple Clang primary
evidence rather than Linux-produced Mach-O evidence.

`c-nonapple-baseline-v1` freezes the nine locally qualified routes as the
current executable width denominator. `worker.toml` refers to those routes by
stable `managed_toolchain_route` IDs; it does not commit cache paths. At load
time the worker recomputes the route-material digest, validates the
qualification record, resolves the compiler, archiver and derived ranlib
beneath the checksum-addressed prepared root, and places both the material and
qualification-record digests in resolved cells. A missing or altered pack is
visible but blocked from execution.

## Linux pack preparation

From the Linux x86-64 coordinator checkout:

```sh
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
./scripts/toolchains/pull.sh c-top10-linux
./scripts/toolchains/prepare.sh c-top10-linux
./scripts/toolchains/qualify.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
```

`plan` and `status` are read-only. Pull verifies reviewed URLs, exact byte
counts, and SHA-256 values. Prepare rejects unsafe archives before atomic
publication. Qualify resolves only reviewed tools and runs fixed language,
archive, and target-format probes. The GUI is an inspector for this lifecycle;
it does not install toolchains.

Profile state is intentionally more precise than installed/not-installed:

| State | Meaning |
| --- | --- |
| `acquisition-required` | One or more reviewed archives must be pulled. |
| `preparation-required` | Cached archives require safe extraction. |
| `composition-required` | A reviewed multi-pack route requires composition. |
| `qualification-required` | One or more local routes require fixed probes. |
| `qualified-external-required` | Linux-managed routes passed; an external native worker must register. |
| `qualified` | All routes in the profile are locally qualified. |
| `blocked` | Authority, integrity, or host checks failed closed. |

`recommended_next_action` is the machine-followable transition. For the
current top-ten profile, the final transition is `start-external-workers`; it
does not mean that a run should be armed.

`plans/c-nonapple-zlib-canary-v1.toml` is the disarmed execution proof for the
frozen baseline: one fixed zlib release, one O2 treatment and all nine managed
routes. Resolve it before execution; its cells are blocked automatically if a
qualification identity cannot be recovered.

## Route/toolchain canary (superseded as width evidence)

`coverage/c-route-toolchain-canary-v1.toml` fixes zlib 1.3.1 and the non-Apple route profile,
then names all four artifact shapes, six analysis profiles, three admission
profiles and two selected replays. `coverage/universe.toml` maps the bounded
O0/O2/O3/Os, frame-pointer and stack-protection profiles to reviewed worker
treatments for each compatible compiler family.

This authority is explicitly a route/toolchain canary. It proves that nine
target/toolchain routes, six treatments, two replays, object extraction and
Ghidra FID production work end to end. Because each target used only one
compiler build, it does not measure compiler-family or compiler-generation
hash coverage and is not substantive `c-width-v1` evidence.

The substantive compiler-width subject is OpenSSL 3.5.8, the rank-one family
in the frozen top-ten study. `recipes/openssl.toml` pins the official LTS
archive and checksum. The fixed `openssl-configure` adapter selects a reviewed
OpenSSL platform target from the route's OS/architecture, disables shared
libraries, tests, documentation and modules, and builds `libcrypto.a` plus
`libssl.a`. Recipes still cannot provide commands.

`coverage/c-width-v1.toml` is the disarmed substantive authority. It combines
that OpenSSL release with `c-compiler-width-v1`, the six bounded treatments,
static archive members and the registered FID-safe analysis/admission lane.
Compile it without executing anything:

```sh
fidb-poc compile-width --project-root . --output /tmp/c-width-v1.json
```

The output retains four distinct states for each route/profile pair:
`executable`, `unimplemented`, `unavailable`, and `inapplicable`. It also
projects every one of the 41 sensitivity factors, including factors with no
named variant yet. The GUI renders the same route-by-profile map and the full
factor ledger. Once all 29 selected routes are qualified, the compiler resolves
174 feasible build/analysis cells: six treatments for each route and one
selected replay. The 4,800-build theoretical one-family maximum remains
visible as capacity intent, not executable work.

Preview the exact measured-run schedule without downloading or compiling:

```sh
fidb-poc run-width --project-root .
```

The command is disarmed by default. The first live gate is the fixed OpenSSL
baseline treatment across every qualified selected compiler route:

```sh
fidb-poc run-width --project-root . --canary --execute
```

Only after that succeeds should the complete feasible width be run:

```sh
fidb-poc run-width --project-root . --execute
```

Each live invocation creates a new immutable run directory under
`artifacts/width-runs/c-width-v1/`; it never replaces an earlier run. The full
run executes the 174 applicability-approved route/profile cells once. Each
cell has an isolated work and artifact root, while a bounded process pool runs
independent embedded Ghidra JVMs concurrently. Width runs now add a measured
4 GiB maximum heap to each JVM unless an equivalent inherited `-Xmx` already
exists. A conflicting inherited maximum fails closed. The old ergonomic route
is preserved for controlled comparison with `--unbounded-ghidra-heap`; it is
not the safe default. The default worker count remains the lowest of the CPU
bound, one worker per 8 GiB of currently available host RAM, and twelve;
override it explicitly with `--workers N` only after checking a measured peak.
On `reference-host`, Linux currently sees about 94 GiB after the graphics allocation,
so the automatic starting width is eight workers.

Successful cells discard reproducible bulk source, build and Ghidra-project
scratch after measuring it. After the process pool exits, application logs are
gzip-archived under each group and the reproducible Ghidra user cache is
discarded; the cleanup byte counts remain in the result. Published artifacts,
manifests and diagnostics are retained. A durable `replay-progress.json`
checkpoint is rewritten after every returned cell. The completed run
writes `width-run.json` with wall time, peak and final scratch size, retained
size, peak process RSS, per-cell failures, and coverage contribution. Per-cell
FID signatures are retained for unique and marginal-coverage comparison; raw
FIDB container hashes are not used as a proxy for function coverage.

The 29-worker OpenSSL pressure benchmark reclaimed 516,191,925 bytes of JVM
user state after archiving 10,166,655 bytes of application logs and retained
241,859,821 bytes for the complete benchmark directory. Cleanup happens only
after every worker process exits, never while its embedded JVM is live.

Every completed cell publishes a deterministic `fid-signatures/*.jsonl`
ledger. Its comparison identity is Ghidra language, full hash, specific hash,
specific-hash additional size and code-unit size; function name and object
domain path remain attached as diagnostic evidence. The run summary reports
union and exclusive signature counts by compiler and treatment, compiler
marginals within each fixed target/treatment, treatment marginals within each
fixed route, and clean pairwise comparisons along both axes. Wall time and
retained bytes are attached to the same cells, yielding marginal/exclusive
signatures per wall hour. The report explicitly lists one-percent-or-less
marginal members and pairs at Jaccard 0.98 or higher as candidates for an
over-stressed factor; these are evidence for review, not automatic deletion.
The broader same-target overlaps remain available too. Preserving the raw
function evidence means later thresholds and regrouping do not require
recompilation.

### Bounded width-pipeline benchmarks

`benchmark-width` executes an explicitly selected subset of the reviewed
OpenSSL width without presenting it as coverage evidence. Preview is the
default; `--execute` is required to build or start Ghidra. Results live under
`artifacts/benchmarks/width-pipeline/`, outside the lane compiler's
`artifacts/width-runs/` input boundary.

```sh
fidb-poc benchmark-width --project-root . \
  --label x86-arm-baseline \
  --route linux-x86-64-gcc-13 \
  --route linux-arm32-gcc-13 \
  --treatment baseline_o2 \
  --treatment optimization_o3 \
  --workers 4 \
  --ghidra-heap-mib 4096 \
  --ghidra-core-limit 2
```

The result records per-stage wall/CPU/RSS evidence, aggregate hashes per wall
hour, peak process-tree RSS and scratch, the JVM's observed maximum and
committed heap, and a semantic digest over every selected cell's deterministic
FID-signature ledger. Configurations may be compared only when their selected
routes, treatments and semantic digest agree.

The 2026-09-02 `reference-host` comparison is retained in
`benchmarks/ghidra-heap-reference-host-2026-09-02.toml`. On the same x86-64 GCC 13
OpenSSL cell, 4 GiB reduced peak RSS from 6,269,710,336 to 2,720,817,152 bytes
(56.60%) while increasing wall time from 706.14 to 718.66 seconds (1.77%). The
signature count, unique-signature count and semantic digest were identical. A
ten-route/ten-worker pressure case then completed in 843.19 seconds at
24,613,445,632 bytes peak aggregate RSS and 568,068 signature records/hour.
Every compiled-artifact and signature-ledger digest matched the corresponding
cell in the earlier uncapped full-width run. This evidence adopts the heap
bound; it does not yet justify a worker count above ten.

### Frozen route/toolchain-canary measurement

The 2026-09-02 `reference-host` run completed all 108 scheduled executions: nine
routes by six build profiles by two isolated replays. It took 492.46 seconds
(8m12.46s), peaked at 1,356,658,659 bytes of active-replay scratch and
7,457,091,584 bytes of process RSS, retained 2,684,774,362 bytes of final
scratch across both replays, and produced 1,852,298 bytes beneath the retained
FIDB/manifest roots. There were no build or FID failures.

Replay comparison found byte-identical object sets in 48 of 54 cells: all
eight ELF routes repeated exactly, while all six PE/COFF profiles did not.
FID semantic counts repeated in 53 of 54 cells. SH4 `-Os` added the same 137
functions in both runs but attempted/excluded counts differed by eight. Raw
FIDB container bytes differed in all 54 cells and are therefore tracked
separately from semantic results. The checksum-bound compact record is
`coverage/evidence/c-route-toolchain-canary-v1-reference-host-2026-09-02.toml`.

A deliberately naive linear projection puts the same width over ten libraries
at about 1h22m and 26.85 GB final scratch, and over 80 libraries at about 10h57m
and 214.78 GB final scratch. Those are calibration projections, not an ETA:
the top-10 run must measure cross-library batching, caching, corpus size, and
failure-retry effects before the 80-library plan is fixed.

## Current non-Apple qualification

On 2026-09-02, `reference-host` qualified all nine Linux-managed routes at revision
`17886c1c211c6fc78cda25c1c96cb2b507c83375`. Each route emitted both C and
C++17 objects with the expected target identity and a static `ar` archive.
The result was 9 qualified routes, 0 missing qualifications, 0 broken routes,
and one deliberately deferred external Apple route. No library or FIDB batch
had been executed at the point that qualification record was written; the
later route/toolchain-canary measurement above is separate evidence.

The compact audit record is
`toolchains/evidence/c-top10-linux-reference-host-2026-09-02.toml`. Full records and
smoke objects remain host-local beneath `var/fidb-toolchains/qualified/` so a
clone cannot inherit qualification without possessing and checking the tools.
Re-run `status`, `qualify`, and `status` on another Linux x86-64 host; matching
profile, route-material, and qualification-record digests provide the
reproducibility comparison.

## Compiler identity is a separate axis

`toolchains/compilers.toml` is the target-independent compiler registry. A
route in `toolchains/routes.toml` binds one `compiler_id` to one `target_id`,
then names the exact downloadable pack, linker, runtime/sysroot and target
triple. The GUI and compiled matrix must therefore report target and compiler
identity as separate fields; neither a target label nor a generic `gcc` route
may stand in for compiler-generation width.

The compiler ID is validated against the qualification pack's family and exact
version. Qualification records remain content-addressed by the full pack
material, so the added explicit ID does not invalidate an otherwise identical
existing qualification.

## First compiler-generation width

`toolchains/compiler-width.toml` records both the historical releases found
for each target and the bounded first selection. The executable selection is
three GCC generations on every Linux target and five spaced llvm-mingw Clang
generations on Windows x86-64:

| Target set | Compiler identities | Routes |
| --- | --- | ---: |
| Eight Linux ELF targets | GCC 12.3.0, 13.3.0, 14.3.0 | 24 |
| Windows x86-64 PE/COFF | Clang 15.0.0, 17.0.6, 19.1.6, 20.1.7, 23.1.0 | 5 |

The profile is `c-compiler-width-v1`: 29 routes backed by 29 immutable packs.
On the already-qualified host, the twenty additions require 2,096,928,160
download bytes and extracted to 9,038,458,683 bytes. Across all 29 packs, the
measured prepared payload is 12,890,591,603 bytes. Acquire them through the
same project-local lifecycle:

```sh
./scripts/toolchains/plan.sh c-compiler-width-v1
./scripts/toolchains/pull.sh c-compiler-width-v1
./scripts/toolchains/prepare.sh c-compiler-width-v1
./scripts/toolchains/qualify.sh c-compiler-width-v1
./scripts/toolchains/status.sh c-compiler-width-v1
```

The 2026-09-02 `reference-host` qualification completed all 29 routes with no
missing or broken record. Its compact audit snapshot is
`toolchains/evidence/c-compiler-width-v1-reference-host-2026-09-02.toml`; full smoke
objects and records stay in the checksum-addressed host-local store.

This is an intentional first tranche, not a claim that compiler width is
complete. ELF Clang paired with explicit target sysroots, GNU MinGW GCC,
native MSVC and Apple Clang remain named denominator gaps. The first OpenSSL
measurement determines which existing generations and treatments contribute
enough new FID signatures to retain before those families are added.

## Android NDK width on Linux

`c-android-width-v1` adds the complete current Android ABI set without moving
execution off `reference-host`:

| Broad analyst lane | ABI sublane | NDK/compiler routes |
| --- | --- | --- |
| `android-arm` | armeabi-v7a, arm64-v8a | r27d/Clang 18.0.4 and r29/Clang 21.0.0 |
| `android-x86` | x86, x86-64 | r27d/Clang 18.0.4 and r29/Clang 21.0.0 |

API 21 is explicit in every route ID, target wrapper and OpenSSL Configure
invocation. Target and compiler identity therefore remain separate axes:
four ABI requirements become eight executable routes. Each NDK archive
contains every ABI sysroot, so the profile downloads only two official Google
archives: 1,447,505,517 bytes compressed and 4,548,615,143 measured extracted
file bytes.

Reproduce the project-local lifecycle on Linux x86-64 with:

```sh
./scripts/toolchains/plan.sh c-android-width-v1
./scripts/toolchains/pull.sh c-android-width-v1
./scripts/toolchains/prepare.sh c-android-width-v1
./scripts/toolchains/qualify.sh c-android-width-v1
./scripts/toolchains/status.sh c-android-width-v1
```

All eight routes qualified on `reference-host` on 2026-09-02. Qualification compiled
fixed C and C++17 objects, checked ELF bitness, endianness and machine IDs, and
created static archives. The worker resolves only those qualification records;
its OpenSSL adapter selects `android-arm`, `android-arm64`, `android-x86` or
`android-x86_64`, sets the matching reviewed `ANDROID_NDK_ROOT` and tool `PATH`,
and pins `-D__ANDROID_API__=21`. A disarmed plan reports all eight OpenSSL cells
as runnable, but no Android library or Ghidra batch was executed here.

The repository records official URLs, exact sizes, SHA-256 values, upstream
release identities and licence classifications. It does not commit or
redistribute NDK archives or extracted SDK files; those remain ignored beneath
`var/fidb-toolchains/`. Operators must review and accept the terms applicable
to their own download and use. The qualification audit record is
`toolchains/evidence/c-android-width-v1-reference-host-2026-09-02.toml`.

## Native Apple worker

The public project does not download, package, bind, copy, or redistribute an
Apple SDK. Xcode and the macOS SDK remain installed and used on Apple-branded
hardware running macOS. This is a deliberate technical boundary informed by
Apple's [Xcode and Apple SDKs Agreement](https://www.apple.com/legal/sla/docs/xcode.pdf);
each operator remains responsible for the terms applicable to their use.

The reviewed definition is
`toolchains/external/macos-arm64-apple-clang.toml`. It declares:

- the `macos-native` worker pool and `macos-native-remote` class;
- Darwin/ARM64 host and Mach-O/ARM64 target identities;
- the fixed `apple-xcode` probe adapter;
- current `c` and `cpp` capabilities;
- deployment target, required tools and provenance fields; and
- worker-specific memory, disk, and load floors.

No TOML field contains a command. Adding another language to the protocol
means adding a reviewed language profile and a fixed probe implementation,
then declaring that capability in an external definition. It does not grant a
caller or an LLM arbitrary command execution.

On the M1 Max, use a local checkout at the exact reviewed Linux coordinator
revision. Do not use the Samba-mounted checkout as build scratch. The Samba
path mapping remains useful for inspection:

```text
Linux: /home/fidb-operator/Projects/circl/FIDB-POC-unified
macOS: /Volumes/linux-home-share/Projects/circl/FIDB-POC-unified
```

Prepare the Mac without contacting the coordinator:

```sh
./scripts/workers/macos-preflight.sh
```

The preflight checks Apple hardware, macOS ARM64, Xcode, SDK and Apple Clang
identity, Java 21+, Ghidra, PyGhidra, local resource floors, C and C++ ARM64
Mach-O objects, and a static archive. Its JSON includes the external-definition
digest and required provenance metadata.

When a run is later approved, install a private environment from
`operations/macos-worker.env.example`, authorize that worker credential only
for `macos-native`, expose the Linux worker API through reviewed tailnet-only
HTTPS, synchronize the still-reviewed queue, and use:

```sh
./scripts/workers/macos-run.sh --until-drained
```

That command is documented for future execution; preparing this repository
does not run it or arm the queue. The Mac initiates the connection, so the
Linux coordinator never SSHs into the Mac.

## How Mac results return to Linux

The Linux coordinator remains the source of truth:

```text
reviewed cell on Linux
  -> authenticated macos-native lease
  -> native build + Ghidra analysis on Mac
  -> result.fidb + result.fidbf + cell-seal.json
  -> authenticated upload staging on Linux
  -> lease/cell/path/size/digest/seal/timing validation
  -> atomic artifacts/runs/<job-id>/attempt-<generation>/ publication
  -> SQLite result references and GUI evidence view
```

The Mac never opens or copies the coordinator SQLite database. The Linux host
does not receive Xcode, the SDK, signing material, Apple credentials, source
trees, or build scratch. Heartbeats preserve the registered toolchain
capabilities so the GUI can show worker online/offline state and the exact
Xcode, SDK, compiler, Ghidra, Java, host, definition digest, and supported
languages used by an attempt.

Artifacts are transferred as idempotent 8 MiB chunks. Linux records the whole
artifact identity, durably resumes from an existing partial upload, and checks
the final whole-file SHA-256 before publication. The default safety ceiling is
4 GiB per artifact; an extended-run review must still compare expected output
sizes and coordinator free space with that explicit limit.

## Deliberately disarmed canary

`plans/macos-arm64-canary.toml` defines one zlib/Apple-Clang/Mach-O cell.
`plans/priority-queue.toml` references it but remains `armed = false`.
Synchronizing a disarmed queue only materializes intent; it does not claim or
execute a cell. Before any later run, inspect the resolved plan, Mac preflight,
credential scope, HTTPS boundary, disk headroom, and upload-size risk, then
explicitly review the arming change.

## Storage and committed authority

Linux-managed runtime material is ignored beneath `var/`:

```text
var/fidb-toolchains/downloads/   verified upstream archives
var/fidb-toolchains/prepared/    safely extracted pack roots
var/fidb-toolchains/composed/    reviewed derived routes, when defined
var/fidb-toolchains/qualified/   qualification records and smoke artifacts
var/fidb-remote-upload-locks/    coordinator-local transfer serialization
artifacts/runs/remote-staging/   incomplete authenticated uploads
artifacts/runs/                  atomically published sealed attempts
```

The Mac uses its own ignored `var/fidb-remote-worker/` attempt scratch. Only
the three sealed outputs return to Linux.

Git contains the reproducibility contract:

- `toolchains/packs.toml`: downloadable archives and size evidence;
- `toolchains/routes.toml`: target/compiler/provisioning mappings;
- `toolchains/qualifications.toml`: fixed local route probes;
- `toolchains/profiles/*.toml`: language-scoped ordered breadth;
- `toolchains/external/*.toml`: native worker definitions and capabilities;
- `worker.toml`: typed executable native routes; and
- `scripts/toolchains/` and `scripts/workers/`: typed operator entrypoints.

## Extending to more languages or platforms

1. Define the language and its finite treatment policy in the coverage
   authority; do not reuse the C multiplier implicitly.
2. Add or reuse target/compiler requirements and a language-scoped profile.
3. For a downloadable route, pin the pack and add fixed qualification probes.
4. For a platform-restricted route, add a command-free external TOML and a
   reviewed fixed probe adapter; declare its language capabilities explicitly.
5. Add a pool-routing test, one disarmed canary plan, and GUI projection.
6. Run the backend suite and control-panel build before any acquisition or
   execution is authorized.

Automation and future LLM operators consume stable JSON identities and invoke
typed operations only. They may select reviewed IDs and surface blockers; they
may not invent URLs, checksums, commands, credentials, worker pools, or route
capabilities.

See `toolchains/README.md` for the catalogue schema and
`toolchains/external/README.md` for the external-worker boundary.
