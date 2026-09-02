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

The nine downloadable archives total 753,465,840 bytes. Their current
prepared-size estimate is 3,013,863,360 bytes. The macOS worker's Xcode,
Ghidra, build scratch, and temporary output are additional host-local capacity,
not part of the Linux pack estimate.

`c-top10-reference` uses the same ten target requirements and adds native MSVC
as a second Windows implementation. Cross-built PE/COFF never claims native
MSVC equivalence. The macOS route is deliberately native Apple Clang primary
evidence rather than Linux-produced Mach-O evidence.

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
