# Portable toolchain packs

This directory is the reviewed, cloneable authority for acquiring compiler
inputs used to widen FIDB experiments. It separates four things that must not
be conflated:

1. A **pack** is one immutable upstream archive, pinned by HTTPS URL, SHA-256,
   exact compressed byte count, component versions, target, licence summary and
   an explicitly classified installed-size estimate.
2. A **route** composes one or more packs for a target/compiler pair, or records
   that the route needs an external native worker.
3. A **profile** is a language-owned, ordered set of routes. It is the portable
   unit an operator or automation requests.
4. A **profile plan** is the canonical JSON projection of that authority plus
   this host's read-only cache state. Its `profile_digest` excludes cache state,
   so the identity does not change after download.

The original `registry.toml` remains the production authority for the current
libc archive/source-cell worker. The pack authority is the wider acquisition
layer for the C route study; it does not silently make those routes executable.

## Current profiles

| Profile | Purpose | Routes | Downloadable packs | Exact compressed bytes | Expanded estimate |
| --- | --- | ---: | ---: | ---: | ---: |
| `c-canary` | One Linux x86-64 acquisition check | 1 | 1 | 93,215,060 | 372,860,240 |
| `c-top10-linux` | Complete first-ten C route denominator | 10 | 8 | 669,585,280 | 2,678,341,120 |

The top-ten profile deliberately reports two external routes alongside the
eight Linux-hosted downloads:

- macOS ARM64 needs a pinned Xcode, Apple Clang, SDK and deployment target on a
  native macOS worker.
- Windows x86-64 needs a pinned MSVC toolset, Windows SDK, linker and CRT on a
  native or separately validated Windows worker.

Those constraints stay in the profile and GUI. They are never treated as
download failures and never disappear from the coverage denominator.

## Operator workflow

Run from any Linux x86-64 checkout:

```sh
# Read authority and cache state; make no changes.
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux

# Download the eight reviewed archives into var/fidb-toolchains/downloads/.
./scripts/toolchains/pull.sh c-top10-linux
```

The wrappers locate the checkout themselves and invoke the typed CLI. Their
first argument is only a reviewed profile ID. `pull` resolves all URLs and
digests from TOML, serializes concurrent downloads by SHA-256, applies bounded
retries and size limits, verifies before publication, and uses an atomic rename.
An invalid existing cache entry is quarantined instead of overwritten in place.

The output is JSON using `fidb-toolchain-profile-plan/v1`. Useful top-level
fields for humans and automation are:

- `profile_digest` and `catalog_digest` for identity;
- `state`, `recommended_next_action` and structured `requirements` for control;
- `summary` for route counts and disk planning;
- `packs[].state` for `missing`, `verified-cached`, or `broken`;
- `routes[].state` for acquisition and external-worker state;
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
   downloadable route must reference a compatible pack. An external route must
   contain no pack and must enumerate its native-worker requirements.
3. Add or widen a file in `profiles/`. Give it a `language_id`, a Linux x86-64
   host contract, an ordered unique route list, and a width-study authority.
   Profile routes must be a subset of that study's ordered requirements.
4. Run `./scripts/toolchains/plan.sh PROFILE`. Loading is strict: unknown fields,
   duplicate IDs, bad digests, unknown targets/compilers/packs/routes, mismatched
   pack targets and missing authority paths all fail closed.
5. Run the unit suite and control-panel build before review. Only after review
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
