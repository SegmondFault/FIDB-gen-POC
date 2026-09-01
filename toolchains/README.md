# Portable toolchain packs

This directory is the reviewed, cloneable authority for acquiring and
qualifying compiler inputs used to widen FIDB experiments. It separates six things that must not
be conflated:

1. A **pack** is one immutable upstream archive, pinned by HTTPS URL, SHA-256,
   exact compressed byte count, component versions, target, licence summary and
   an explicitly classified installed-size estimate.
2. An **input** records a required component that the project does not
   redistribute, such as an operator-supplied Apple SDK and its required pin
   metadata.
3. A **route** composes packs and inputs for a target/compiler pair, or records
   that the route needs an external native worker. Its evidence role says
   whether it is primary, cross-build, or native-reference evidence.
4. A **profile** is a C-family, ordered set of routes. It is the portable
   unit an operator or automation requests.
5. A **qualification** fixes the compiler, C++ compiler, archiver, expected
   version marker, composition method and C-family smoke languages for one
   locally buildable route. It is authority, not a claim that the route passed.
6. A **profile plan** is the canonical JSON projection of that authority plus
   this host's read-only cache state. Its `profile_digest` excludes cache state,
   so the identity does not change after download.

The active programme covers C libraries and C APIs, with C++ included only when
one of those libraries requires it. No standalone C++ or other-language pack
campaign is active. The original `registry.toml` remains the production
authority for the current libc archive/source-cell worker. The pack authority
is the wider acquisition layer for the C route study; it does not silently make
those routes executable.

## Current profiles

| Profile | Purpose | Requirements / implementations | Archives | Exact compressed bytes | Prepared estimate |
| --- | --- | ---: | ---: | ---: | ---: |
| `c-canary` | One Linux x86-64 acquisition check | 1 / 1 | 1 | 93,215,060 | 372,860,240 |
| `c-top10-linux` | First-ten targets from a Linux acquisition host | 10 / 10 | 11 | 2,692,424,622 | 15,064,665,784 |
| `c-top10-reference` | Same target breadth plus native compiler references | 10 / 12 | 11 | 2,692,424,622 | 15,064,665,784 + external workers |

The Linux-hosted top-ten profile contains:

- eight checksum-pinned Bootlin GCC/binutils/glibc target SDKs;
- llvm-mingw/Clang + LLD + MinGW UCRT for Windows x86-64 C/C++ PE/COFF output;
- upstream LLVM/Clang and pinned osxcross source for macOS ARM64 Mach-O output;
  and
- an explicit Apple SDK input gate. The operator must bind Xcode version, SDK
  version, deployment target, `tar-xz` package format, SHA-256, and byte count
  because the project does not redistribute that SDK.

The reference profile then adds native Apple Clang and MSVC workers. These are
separate route implementations for the same target requirements: cross-built
Mach-O and PE/COFF evidence never claims native-compiler equivalence. Every
constraint stays in the profile and GUI; none disappears from the denominator.

## Operator workflow

Run from any Linux x86-64 checkout. A fresh checkout starts at
`acquisition-required`; cloning the repository does not download a toolchain or
an Apple SDK.

```sh
# Read authority and cache state; make no changes.
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux

# Download the 11 reviewed archives into var/fidb-toolchains/downloads/.
./scripts/toolchains/pull.sh c-top10-linux

# Safely extract verified archives into content-addressed prepared roots.
./scripts/toolchains/prepare.sh c-top10-linux

# Separately obtain and package a licensed Apple SDK as tar.xz, then bind it.
./scripts/toolchains/bind-apple-sdk.sh \
  /path/to/MacOSX.sdk.tar.xz SHA256 BYTES XCODE_VERSION SDK_VERSION DEPLOYMENT_TARGET

# Compose the reviewed LLVM-flavour osxcross route from prepared inputs.
./scripts/toolchains/compose.sh c-top10-linux

# Compile fixed C and C++17 objects, validate their target formats, and archive them.
./scripts/toolchains/qualify.sh c-top10-linux

# Confirm the final state and retain the JSON as run-planning evidence.
./scripts/toolchains/status.sh c-top10-linux
```

The wrappers locate the checkout themselves and invoke the typed CLI. Their
profile argument is only a reviewed profile ID. `pull` resolves all URLs and
digests from TOML, serializes acquisition by SHA-256, applies bounded retries
and size limits, verifies before publication, and uses an atomic rename. An
invalid existing cache entry is quarantined instead of overwritten in place.
`prepare` rejects archive traversal, escaping links, special files and excessive
expansion before atomically publishing a sealed root. `bind-apple-sdk.sh` copies
only a locally supplied package into the private content-addressed input store;
it never downloads or redistributes Apple material.

Create the SDK package according to the upstream
[osxcross SDK instructions](https://github.com/tpoechtrager/osxcross/blob/master/README.SDK.md).
The [osxcross build contract](https://github.com/tpoechtrager/osxcross) is the
upstream authority for composition. The step requires these host executables: `bash`, `cmake`,
`make`, `patch`, `xz`, `bzip2`, `cpio`, `git`, `sed`, `awk`, and `tar`. It uses
the pinned prepared LLVM and osxcross source, sets `BUILD_FLAVOR=llvm`, fixes the
ARM64 route and deployment target, captures the build log, and atomically seals
the result. Qualification then resolves only reviewed tool patterns and runs a
fixed compiler-version probe, C compile, C++17 compile and static archive. ELF,
PE/COFF and Mach-O objects must match the target registry before the route can
become `qualified`.

The profile state is an ordered gate, so an operator or LLM can follow
`recommended_next_action` without guessing:

| Profile state | Allowed next step |
| --- | --- |
| `acquisition-required` | `pull` |
| `preparation-required` | `prepare` |
| `input-required` | bind the named private input |
| `input-and-external-required` | bind the input and retain the native-worker gaps |
| `composition-required` | `compose` |
| `qualification-required` | `qualify` |
| `qualified-external-required` | define the separately pinned native workers |
| `qualified` | retain the plan identity and proceed to reviewed run planning |
| `blocked` | repair the structured integrity or host blocker first |

The output is JSON using `fidb-toolchain-profile-plan/v3`. Useful top-level
fields for humans and automation are:

- `profile_digest` and `catalog_digest` for identity;
- `state`, `recommended_next_action` and structured `requirements` for control;
- `summary` for route counts and disk planning;
- `packs[].state` plus `packs[].preparation.state` for download and extraction;
- `inputs[].binding` and structured requirements for non-redistributed SDKs;
- `routes[].state`, `routes[].qualification`, and `evidence_role` for the full
  acquisition-to-qualification lifecycle and native-reference state;
- `cli_examples` for typed, repeatable operations; and
- `trace` for TOML paths and source digests.

`verified-cached`, `prepared`, `bound-verified`, `composed`, and `qualified` are
deliberately distinct. Even `qualified` means only that the reviewed toolchain
passed its fixed target smoke check; it does not admit library builds to a
campaign or claim native-compiler equivalence.

For `c-top10-linux`, the retained planning estimate is about 2.51 GiB of
compressed downloadable archives plus about 14.03 GiB of prepared packs and
route composition, or about 16.54 GiB before temporary atomic staging and small
qualification artifacts. These remain estimates until a real acquisition run
records measured storage; provision additional headroom.

## Extending the catalogue

Add breadth through reviewed data, in this order:

1. Add one `[[pack]]` to `packs.toml`. Pin every component version, target,
   HTTPS archive, upstream SHA-256 and exact byte count. Mark estimates as
   estimates; do not turn them into measured claims.
2. Add one `[[route]]` to `routes.toml`. Its target and compiler family must
   already exist in `targets/registry.toml` and `coverage/universe.toml`. A
   downloadable route must reference a compatible pack. A route that needs a
   non-redistributed component must also reference an entry in `inputs.toml`.
   An external route must contain no pack or input and must enumerate its
   native-worker requirements.
3. Add an `[[input]]` to `inputs.toml` only when acquisition cannot be safely
   automated. Record source policy, authority, and all metadata that an
   operator must bind before qualification.
4. Add one `[[qualification]]` to `qualifications.toml` for every non-external
   route. Reference a route-owned prepared pack or an explicitly supported
   composition, use beneath-root executable patterns that resolve exactly
   once, pin the expected version marker, and select only `c` and `cpp` smoke
   languages. C must always be present.
5. Add or widen a file in `profiles/`. Give it a `language_id`, a Linux x86-64
   host contract, an ordered unique route list, and a width-study authority.
   Multiple implementations may map to one study requirement, but each mapping
   is explicit.
6. Run `./scripts/toolchains/plan.sh PROFILE`. Loading is strict: unknown fields,
   duplicate IDs, bad digests, unknown targets/compilers/packs/inputs/routes,
   missing qualification rows, mismatched targets and missing authority paths
   all fail closed.
7. Run the unit suite and control-panel build before review. Only after review
   should an operator run `pull`.

No TOML file accepts a raw shell command. Execution remains a small typed set of
idempotent operations (`plan`, `status`, `pull`, `prepare`, `compose`, and
`qualify`), which makes the same interface suitable for an LLM or another
orchestrator later: choose a profile ID, inspect the JSON plan, surface
structured blockers, and request only the recommended allowed operation. The
caller never invents an acquisition URL, checksum, extraction path, composition
command, or compiler invocation.
