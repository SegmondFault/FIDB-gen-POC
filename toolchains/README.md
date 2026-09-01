# Portable toolchain packs

This directory is the reviewed, cloneable authority for acquiring compiler
inputs used to widen FIDB experiments. It separates four things that must not
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
5. A **profile plan** is the canonical JSON projection of that authority plus
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
  version, deployment target, SHA-256, and byte count because the project does
  not redistribute that SDK.

The reference profile then adds native Apple Clang and MSVC workers. These are
separate route implementations for the same target requirements: cross-built
Mach-O and PE/COFF evidence never claims native-compiler equivalence. Every
constraint stays in the profile and GUI; none disappears from the denominator.

## Operator workflow

Run from any Linux x86-64 checkout:

```sh
# Read authority and cache state; make no changes.
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux

# Download the 11 reviewed archives into var/fidb-toolchains/downloads/.
./scripts/toolchains/pull.sh c-top10-linux
```

The wrappers locate the checkout themselves and invoke the typed CLI. Their
first argument is only a reviewed profile ID. `pull` resolves all URLs and
digests from TOML, serializes concurrent downloads by SHA-256, applies bounded
retries and size limits, verifies before publication, and uses an atomic rename.
An invalid existing cache entry is quarantined instead of overwritten in place.

The output is JSON using `fidb-toolchain-profile-plan/v2`. Useful top-level
fields for humans and automation are:

- `profile_digest` and `catalog_digest` for identity;
- `state`, `recommended_next_action` and structured `requirements` for control;
- `summary` for route counts and disk planning;
- `packs[].state` for `missing`, `verified-cached`, or `broken`;
- `inputs` and `user-input-required` requirements for non-redistributed SDKs;
- `routes[].state` and `evidence_role` for acquisition, cross-build, input, and
  native-reference state;
- `cli_examples` for typed, repeatable operations; and
- `trace` for TOML paths and source digests.

`verified-cached` means only that the immutable compressed bytes match the
reviewed SHA-256. It does **not** mean extracted, activated, compiler-probed,
ABI-checked, smoke-built, or admitted to a production run.

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
4. Add or widen a file in `profiles/`. Give it a `language_id`, a Linux x86-64
   host contract, an ordered unique route list, and a width-study authority.
   Multiple implementations may map to one study requirement, but each mapping
   is explicit.
5. Run `./scripts/toolchains/plan.sh PROFILE`. Loading is strict: unknown fields,
   duplicate IDs, bad digests, unknown targets/compilers/packs/inputs/routes,
   mismatched targets and missing authority paths all fail closed.
6. Run the unit suite and control-panel build before review. Only after review
   should an operator run `pull`.

No TOML file accepts a raw shell command. Execution remains a small typed set of
idempotent operations (`plan`, `status`, `pull`), which makes the same interface
suitable for an LLM or another orchestrator later: choose a profile ID, inspect
the JSON plan, surface structured blockers, and request an allowed operation.
The caller never invents an acquisition URL, checksum, extraction path or
compiler invocation.

## Next qualification layer

The next implementation phase should add deterministic preparation manifests
without weakening this boundary: safe extraction into content-addressed roots,
expected compiler-path and version probes, target-triple/sysroot checks, a
minimal static-library smoke build per route, measured installed bytes, and a
qualification digest. Until those records exist, the GUI correctly labels the
current routes as acquisition-reviewed rather than executable.
