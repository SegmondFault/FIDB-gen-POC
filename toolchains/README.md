# Toolchain authority

This directory is the reviewed, cloneable authority for compiler and native
worker breadth. It separates six concepts:

Compiler generations are registered independently in `compilers.toml`.
Concrete routes bind `compiler_id` and `target_id` separately so multiple
compiler generations can target the same ABI without being collapsed into one
route label.

1. A **pack** is an immutable upstream archive with URL, SHA-256, exact bytes,
   component versions, target, licences, and a classified size estimate.
2. An **input** is a non-redistributed component accepted by a reviewed route.
   The current authority contains no inputs; in particular, it accepts no
   Apple SDK payload on Linux.
3. A **route** maps one target/compiler pair to downloadable packs or an
   external worker and labels its evidence role.
4. A **profile** is a language-scoped ordered route set.
5. A **qualification** fixes safe local compiler/archive probes. It is
   authority, not evidence that the probe passed.
6. An **external definition** fixes a native worker's host, pool, target,
   probe adapter, language capabilities, metadata, and resources without
   accepting a command.

The profile JSON combines this authority with host-local lifecycle state. Its
digest excludes cache state so acquisition does not change experiment identity.

## Current profiles

| Profile | Requirements / routes | Download packs | Exact bytes | Prepared files | External |
| --- | ---: | ---: | ---: | ---: | --- |
| `c-canary` | 1 / 1 | 1 | 93,215,060 | 460,835,547 | none |
| `c-top10-linux` | 10 / 10 | 9 | 753,465,840 | 3,852,132,920 | native Apple Clang |
| `c-top10-reference` | 10 / 11 | 9 | 753,465,840 | 3,852,132,920 | Apple Clang + native MSVC definition gap |
| `c-compiler-width-v1` | 9 / 29 | 29 | 2,850,394,000 | 12,890,591,603 | none |
| `c-android-width-v1` | 4 / 8 | 2 | 1,447,505,517 | 4,548,615,143 | none |

The nine packs are eight Bootlin GCC/binutils/glibc target SDKs and one
llvm-mingw/Clang/LLD/MinGW UCRT pack. macOS ARM64 is not a pack: its reviewed
definition is `external/macos-arm64-apple-clang.toml`, and Xcode/SDK use stays
on the Apple worker. The prepared figures are measured extracted-file bytes
from the 2026-09-02 qualification cycle, not four-times-compressed estimates.

`evidence/c-top10-linux-reference-host-2026-09-02.toml` records the successful
nine-route qualification at the exact reviewed revision. See
`evidence/README.md` for the distinction between committed audit evidence and
host-local current readiness.

`c-compiler-width-v1` deliberately repeats targets across compiler
generations: GCC 12.3, 13.3 and 14.3 on each of the eight Linux targets, plus
llvm-mingw Clang 15.0, 17.0, 19.1, 20.1 and 23.1 on Windows x86-64. Its twenty
new archives require 2,096,928,160 additional download bytes on a host that
already has the nine baseline packs and extracted to 9,038,458,683 bytes in
the first safe preparation cycle.

`c-android-width-v1` keeps ABI and compiler generation independent: ARM32,
ARM64, x86 and x86-64 are each bound to NDK r27d/Clang 18 and NDK r29/Clang
21 at API 21. One NDK archive supplies all four ABIs, so eight routes require
two packs rather than eight copies. All eight routes are qualified on
`reference-host`; the compact record is
`evidence/c-android-width-v1-reference-host-2026-09-02.toml`.

## Operator lifecycle

```sh
./scripts/toolchains/plan.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
./scripts/toolchains/pull.sh c-top10-linux
./scripts/toolchains/prepare.sh c-top10-linux
./scripts/toolchains/compose.sh c-top10-linux
./scripts/toolchains/qualify.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
```

Substitute `c-android-width-v1` to reproduce the Android lifecycle. The
archives remain in the ignored content-addressed store and are not
redistributed by this repository.

Compose remains a typed lifecycle stage for profiles that define a reviewed
multi-pack composition; the current top-ten profile has none. Each mutating
operation is idempotent and atomically publishes verified state beneath
`var/fidb-toolchains/`. No operation installs globally.

Machine-facing profile state follows `recommended_next_action`:

| State | Next action |
| --- | --- |
| `acquisition-required` | `pull` |
| `preparation-required` | `prepare` |
| `composition-required` | `compose` |
| `qualification-required` | `qualify` |
| `qualified-external-required` | register/start the named reviewed external workers |
| `qualified` | retain identity and proceed to separately reviewed run planning |
| `blocked` | repair the structured blocker |

Useful JSON fields are `catalog_digest`, `profile_digest`, `state`,
`recommended_next_action`, `requirements`, `summary`, `packs[].cache`,
`packs[].preparation`, `routes[].state`, `routes[].qualification`,
`evidence_role`, `cli_examples`, and `trace`.

## External workers

External definitions live in `external/`. They are deliberately independent of
the current language campaign. A definition declares `languages`; the
coordinator registers and displays those capabilities but does not infer that
another language is supported.

The first adapter, `apple-xcode`, has fixed C and C++ checks because those are
the active route capabilities. A future Swift, Objective-C, Rust, or other
route requires a reviewed probe implementation and language-scoped experiment
profile. Editing TOML alone cannot enable an unimplemented probe or execute a
command.

See `external/README.md` and `../docs/architecture/toolchains.md` for Mac
preflight, authentication, queue routing, result integration, legal boundary,
and future run procedure.

## Extending the catalogue

1. Add a `[[pack]]` to `packs.toml`, with immutable identity and honest size
   evidence, or decide that the route must remain external.
2. Add a `[[route]]` to `routes.toml`; its target and compiler must exist in
   `targets/registry.toml` and `coverage/universe.toml`.
3. Add a `[[qualification]]` for every non-external route, using fixed tool
   patterns and explicit smoke languages.
4. For an external route, add a definition under `external/` with a supported
   fixed `probe_kind`, explicit `languages`, required metadata and resources.
5. Add the route to the appropriate language profile. Multiple implementations
   may map to one requirement only when each is explicit.
6. Add a disarmed canary and routing/validation tests.
7. Run `plan`, the backend suite, and the GUI build before reviewing any pull,
   worker start, or queue arming.

Loading is strict: unknown fields, duplicate IDs, unsafe paths, unsupported
probes, bad digests, target/compiler mismatches, missing authority, and changed
definition identities fail closed. TOML never accepts raw shell commands.
