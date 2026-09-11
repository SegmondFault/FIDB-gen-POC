# FIDB Factory

FIDB Factory is an inspectable research system for building, validating and
exporting Ghidra Function ID databases from pinned C-library source releases.
It explores breadth across compilers, compiler generations, targets, ABIs and
bounded build treatments while preserving the provenance of every result.

The current project is larger than a demonstration script. It includes:

- a TOML-authoritative build matrix and campaign programme;
- host-scoped managed and external toolchain/emulator providers;
- local and remote worker coordination with durable SQLite state;
- Ghidra FID/FIDBF production and linked-image reference populations;
- per-cohort machine validation and corpus-level hash-discrimination evidence;
- dry-run-first retention and evidence-preserving recovery; and
- safeguarded, checksum-verified database export.

The active research programme is focused on C libraries. Some libraries contain
or expose C++ code, but additional language programmes are future work.

## How the pieces fit

```text
reviewed source + recipe + target + toolchain + treatment
                          │
                          ▼
                 exact resolved build cell
                          │
                compile and validate objects
                          │
                 Ghidra analysis and FID
                          │
                   sealed cell evidence
                          │
          validation ─────┼───── retention
                          │
                lane/index construction
                          │
                  safeguarded export
```

TOML records intent. The coordinator ledger records mutable execution state.
Seals, checksums and manifests record what actually happened. None of those
layers is inferred from another merely because a file exists.

## Start here

The complete documentation map is in [`docs/README.md`](docs/README.md).

| Subject | Document |
| --- | --- |
| End-to-end build path | [`docs/architecture/pipeline.md`](docs/architecture/pipeline.md) |
| Toolchain packs and targets | [`docs/architecture/toolchains.md`](docs/architecture/toolchains.md) |
| Emulator providers | [`emulators/README.md`](emulators/README.md) |
| Lane databases and compaction | [`docs/architecture/lane-databases.md`](docs/architecture/lane-databases.md) |
| Machine/ecological validation | [`validation/README.md`](validation/README.md) |
| Hash discrimination | [`docs/validation/hash-discrimination.md`](docs/validation/hash-discrimination.md) |
| Retention and garbage collection | [`docs/operations/retention.md`](docs/operations/retention.md) |
| Database export | [`docs/operations/export.md`](docs/operations/export.md) |
| Operator recovery | [`operations/RECOVERY_RUNBOOK.md`](operations/RECOVERY_RUNBOOK.md) |
| Maintainer and agent entrypoint | [`AGENTS.md`](AGENTS.md) |
| Detailed agent handoff | [`docs/operations/agent-runbook.md`](docs/operations/agent-runbook.md) |
| Generated artifact boundaries | [`docs/artifact-boundaries.md`](docs/artifact-boundaries.md) |
| Proposed engineering improvements | [`dev_notes.md`](dev_notes.md) |

Historical design notes live under `docs/history/`. They explain why decisions
were made but are not current execution authority.

## Repository layout

```text
src/fidb_poc/       Python worker, coordinator, validation and export code
ghidra_scripts/     Ghidra-side analysis and FID scripts
control-panel/      Web control panel
recipes/            Reviewed library and malware build recipes
sources/            Source acquisition authorities and locks
targets/            Target/ABI catalogue
toolchains/         Toolchain routes, packs, profiles and qualifications
emulators/          Host-scoped managed and external emulator providers
performance/        Host detection and execution profiles
batches/            Reviewed width-batch definitions
campaigns/          Long-horizon corpus programmes
plans/              Reviewed plans plus deterministic materialisations
validation/         Validation methods, schedules and evidence contracts
lanes/              Lane and sublane definitions
retention/          Retention policy
export/             Export authority
operations/         Service templates and recovery procedures
docs/               Stable documentation and historical records
tests/              Backend regression tests
```

Generated `artifacts/`, `var/` and `work/` trees are local state. They are not
part of a source-only checkout and must be transferred through their own
evidence or export manifests.

## QEMU and host compatibility

The control plane is not tied to the host that performs compilation. Workers
advertise their host, toolchain and emulator capabilities, and the scheduler
must assign only compatible work. The first managed emulator provider is the
standard static QEMU user-mode suite for an x86-64 Linux worker; it is one
provider implementation, not a project-wide platform requirement.

On a matching host, pull and inspect the checksum-pinned provider without a
global package installation or `binfmt_misc` registration:

```sh
uv run fidb-poc emulator status --project-root .
uv run fidb-poc emulator pull --project-root .
uv run fidb-poc emulator status --project-root . --probe
```

An existing QEMU installation on another host can be declared in the ignored
`emulators/local.toml` using [`emulators/local.example.toml`](emulators/local.example.toml).
The resolved executable paths, versions and SHA-256 values become provenance.
If a host has neither a matching managed provider nor an external one, the
control plane remains usable and execution can be dispatched to a compatible
worker.

## Development setup

Python 3.10 or newer is supported and the locked environment is managed with
`uv`. The current complete production matrix is qualified on an x86-64 Linux
worker; other hosts can operate the control plane, declare compatible local
providers, or dispatch execution to remote workers.

```sh
uv sync --locked
uv run fidb-poc --help
```

Read-only health checks:

```sh
uv run fidb-poc queue status --full
uv run fidb-poc queue doctor --include-inactive --services
uv run fidb-poc materialize-batches --project-root . --check
```

Backend verification:

```sh
uv run python -m unittest discover -s tests -q
uv run black --check src tests ghidra_scripts
```

Control-panel verification:

```sh
cd control-panel
npm ci
npm run test
npm run lint
npx tsc --noEmit
npm run build
```

Note: The control panel is mostly a collection of ideas of what a future control panel could/should look like. It needs a solid tidy up, though it is useful as an aide memoir on the many noving parts.

See [`operations/README.md`](operations/README.md) for installing and operating
the coordinator, workers and control panel. Do not arm work merely to test the
interface; use the read-only checks and disarmed materialisers first.

## Authority and safety

The caller selects reviewed identities. It cannot provide a compiler command,
source URL or shell fragment. The worker resolves those identities through
versioned TOML, validates pinned source bytes and compiler identity, checks
output formats and rejects incomplete or mismatched provenance.

Pinned source archives still contain upstream build logic such as `configure`
scripts and Makefiles. A digest proves which bytes were used; it does not make
them safe. The current system assumes reviewed upstreams and a controlled,
least-privileged build host. It is not a sandbox for hostile source.

Apple SDK material is never redistributed by this repository. Apple-targeted
work crosses the documented external-worker boundary and remains subject to the
applicable Apple agreements.

## Generated data and rollback

Never delete evidence-bearing output just to clean `git status` or recover disk
space. Use the retention collector, review its dry run, honour holds and verify
that lane/import/export relationships have durable receipts before applying a
cleanup plan.

Experimental database compaction, matching engines and validation policies keep
their inputs and previous generations so that results can be ablated or rolled
back. The stable contracts are documented; experiment histories are retained
under `docs/history/`.

## Licence

The project is licensed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE). Project lineage and contribution attribution are recorded
in [`CONTRIBUTORS.md`](CONTRIBUTORS.md) and the Git history.
