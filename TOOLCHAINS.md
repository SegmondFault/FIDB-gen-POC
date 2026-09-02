# FIDB toolchains

FIDB keeps the compiler breadth used by the C-library study inside a
reproducible, project-local toolchain system. A profile describes the required
target/compiler routes; reviewed TOML pins downloadable materials; the CLI
acquires, prepares, composes, and qualifies them; and the GUI projects the same
state for operators. Nothing in this workflow installs a compiler globally.

The active programme is for C libraries and C APIs. C++ is included where an
in-scope library requires it, but this is not a general multi-language
toolchain campaign.

## Quick start

Run the workflow on a Linux x86-64 host from the repository root:

```sh
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
./scripts/toolchains/pull.sh c-top10-linux
./scripts/toolchains/prepare.sh c-top10-linux
```

The `c-top10-linux` profile then pauses at `input-required` until an operator
supplies an Apple macOS SDK. After binding that private input, finish the local
routes with:

```sh
./scripts/toolchains/compose.sh c-top10-linux
./scripts/toolchains/qualify.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
```

Every command emits structured JSON. `plan` and `status` are read-only. The
other operations are idempotent and publish verified results atomically.

## What the top-ten profile contains

`c-top10-linux` covers ten ordered C target requirements with eleven archives:

| Route group | Compiler/toolchain | Output |
| --- | --- | --- |
| Linux x86-64 | Bootlin GCC, binutils, and glibc | x86-64 ELF |
| Linux ARMv7 | Bootlin GCC, binutils, and glibc | ARM32 little-endian ELF |
| Linux AArch64 | Bootlin GCC, binutils, and glibc | AArch64 ELF |
| Linux MIPS | Two Bootlin GCC packs | MIPS32 big- and little-endian ELF |
| Linux PowerPC | Bootlin GCC, binutils, and glibc | PowerPC e500mc ELF |
| Linux SuperH | Bootlin GCC, binutils, and glibc | SH4 ELF |
| Linux M68K | Bootlin GCC, binutils, and glibc | M68K ELF |
| Windows x86-64 | llvm-mingw, Clang, LLD, and MinGW UCRT | PE/COFF |
| macOS ARM64 | LLVM/Clang plus osxcross and an operator-supplied Apple SDK | Mach-O |

The profile has 2,692,424,622 bytes of checksum-pinned downloads. Its retained
prepared/composed planning estimate is 15,064,665,784 bytes, excluding extra
temporary headroom needed for safe extraction and atomic publication.

Cross-compiling PE/COFF or Mach-O on Linux proves those cross-build routes. It
does not claim equivalence with native MSVC or Apple Clang. The
`c-top10-reference` profile keeps native Windows and macOS workers as separate
reference evidence for the same target requirements.

## Lifecycle and states

The lifecycle deliberately separates possession of an archive from evidence
that a compiler route works:

1. **Plan** resolves a reviewed profile and reports its identity, requirements,
   host compatibility, disk estimate, and local state.
2. **Pull** downloads immutable archives by reviewed URL, exact byte count, and
   SHA-256 digest.
3. **Prepare** safely extracts each verified archive into a sealed,
   content-addressed root.
4. **Bind input** copies a non-redistributed operator input, such as an Apple
   SDK, into the same private store and records its provenance metadata.
5. **Compose** builds a reviewed derived toolchain. The current composition is
   the LLVM-flavour osxcross macOS ARM64 route.
6. **Qualify** resolves fixed compiler tools and performs version, C, C++17,
   archive, and target-object-format checks.
7. **Run planning** may use the qualified routes in a separately reviewed
   library experiment. Qualification alone does not admit a route to a batch.

The JSON field `recommended_next_action` is the canonical machine-followable
transition. Typical profile states are:

| State | Meaning |
| --- | --- |
| `acquisition-required` | One or more reviewed archives must be pulled. |
| `preparation-required` | Cached archives still need safe extraction. |
| `input-required` | A private operator input must be bound. |
| `composition-required` | All inputs exist and a derived route can be built. |
| `qualification-required` | One or more local routes need smoke qualification. |
| `qualified-external-required` | Local routes passed; native reference workers remain external. |
| `qualified` | Every route required by the profile is qualified. |
| `blocked` | Integrity, authority, or host checks failed closed. |

Do not collapse `verified-cached`, `prepared`, `bound-verified`, `composed`, and
`qualified` into one installed/not-installed flag. They carry different
evidence and make failures diagnosable.

## Apple SDK handoff

Apple SDK material participates in the same profile, status, composition, and
qualification system, but it is an operator-supplied input rather than a
redistributed pack. The repository commits its input definition and required
metadata, not the SDK payload.

On a Mac with an appropriately licensed Xcode or Apple Command Line Tools
installation:

1. Record the Xcode version with `xcodebuild -version` and the SDK version with
   `xcrun --sdk macosx --show-sdk-version`.
2. Package the SDK as `MacOSX*.sdk.tar.xz` by following the
   [osxcross SDK packaging instructions](https://github.com/tpoechtrager/osxcross/blob/master/README.SDK.md).
   The project pins osxcross commit
   `27d21e4977c9751d01199c7a226a6faf494c3dd9` for composition.
3. Copy the package to this Linux host. When using the `linux-home-share` Samba mount,
   the following paths refer to the same checkout:

   ```text
   macOS: /Volumes/linux-home-share/Projects/circl/FIDB-POC-unified
   Linux: /home/fidb-operator/Projects/circl/FIDB-POC-unified
   ```

   A suitable ignored staging location is
   `var/fidb-toolchains/incoming/` beneath the checkout.
4. On Linux, calculate the exact digest and byte count:

   ```sh
   sha256sum var/fidb-toolchains/incoming/MacOSX.sdk.tar.xz
   stat -c '%s' var/fidb-toolchains/incoming/MacOSX.sdk.tar.xz
   ```

5. Bind the package, replacing every placeholder with the recorded value:

   ```sh
   ./scripts/toolchains/bind-apple-sdk.sh \
     var/fidb-toolchains/incoming/MacOSX.sdk.tar.xz \
     SHA256 BYTES XCODE_VERSION SDK_VERSION DEPLOYMENT_TARGET
   ```

`DEPLOYMENT_TARGET` is an explicit experiment choice, not necessarily the SDK
version. The bind operation checks the supplied size and SHA-256, copies the
package to the content-addressed input store, and writes the
`apple-macos-sdk` binding record. It does not download Apple material.

Confirm the transition before composition:

```sh
./scripts/toolchains/status.sh c-top10-linux
```

The expected next state is `composition-required`. Composition requires the
host tools listed in `toolchains/README.md`, builds only from the pinned LLVM,
osxcross, and bound SDK materials, and seals its output before qualification.

## Project-local storage

Runtime material lives beneath `var/fidb-toolchains/` and is ignored by Git:

```text
var/fidb-toolchains/
├── downloads/   verified upstream archives, keyed by digest
├── prepared/    safely extracted and sealed pack roots
├── incoming/    optional operator staging area
├── inputs/      verified, non-redistributed input payloads
├── bindings/    input metadata and content bindings
├── composed/    derived route toolchains, keyed by route and material identity
├── qualified/   qualification records and smoke artifacts
└── locks/       operation locks
```

This layout makes a checkout self-contained without making large or restricted
payloads part of source control. Removing `var/fidb-toolchains/` removes local
toolchain state, so do not use it as disposable build output when preserving a
prepared installation matters.

The repository commits only the reproducible authority:

- `toolchains/packs.toml` pins downloadable archives and size evidence;
- `toolchains/inputs.toml` defines private inputs and their metadata contract;
- `toolchains/routes.toml` maps packs and inputs to targets and compilers;
- `toolchains/qualifications.toml` fixes the permitted smoke checks;
- `toolchains/profiles/*.toml` selects ordered route breadth; and
- `scripts/toolchains/` exposes the typed operator workflow.

## GUI and automation

The Targets & toolchains GUI reads the same plan/status projection as the CLI.
It should be used to inspect profile breadth, missing materials, lifecycle
state, disk estimates, route evidence roles, and copyable next commands. It is
not a second package manager and currently does not perform installation.

Automation and future LLM operators should use the JSON schema rather than
scraping terminal prose. They select a reviewed profile ID, inspect `state`,
`requirements`, `summary`, and `recommended_next_action`, and invoke only the
corresponding typed operation. TOML never accepts arbitrary acquisition URLs or
shell commands from the caller.

## Extending the matrix

Widen the toolchain system as reviewed data:

1. Define and checksum-pin a pack in `toolchains/packs.toml`, or define a
   non-redistributed input in `toolchains/inputs.toml`.
2. Map it to an existing target and compiler family in
   `toolchains/routes.toml`.
3. Add a fixed qualification row for every locally buildable route.
4. Add the route to the appropriate C-family profile, preserving its explicit
   coverage-requirement mapping and evidence role.
5. Run `plan`, the unit suite, and the GUI build before reviewing any pull.
6. Acquire, prepare, compose if necessary, and qualify only after the authority
   change is reviewed.

See [`toolchains/README.md`](toolchains/README.md) for the complete catalogue
contract, strict validation rules, extension sequence, and machine-facing JSON
fields.

## Checks and troubleshooting

Start with the read-only status command:

```sh
./scripts/toolchains/status.sh c-top10-linux
```

Use its structured requirements instead of manually changing store contents.
An invalid cache entry is quarantined; unsafe archives and escaping links are
rejected; partially prepared or composed outputs are not published as valid.
If the state is `blocked`, retain the JSON and build log, repair the reported
integrity or host dependency, and rerun the same idempotent operation.

For disk inspection on Linux:

```sh
du -sh var/fidb-toolchains/downloads var/fidb-toolchains/prepared \
  var/fidb-toolchains/inputs var/fidb-toolchains/composed 2>/dev/null
df -h .
```

