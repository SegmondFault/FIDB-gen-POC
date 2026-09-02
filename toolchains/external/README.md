# External toolchain workers

External workers keep platform-restricted toolchains inside their permitted
native environment while allowing the Linux coordinator to manage one matrix.
They are not downloadable packs and never place proprietary SDK material in
the repository or `var/fidb-toolchains/` on the coordinator.

The first external definition is
[`macos-arm64-apple-clang.toml`](macos-arm64-apple-clang.toml). It binds the
`macos-arm64-apple-clang` route to the fail-closed `macos-native` worker pool.
The worker must be an ARM64 Apple-branded machine running macOS with Xcode,
Apple Clang, the macOS SDK, Java, PyGhidra, and Ghidra available locally.

The Linux coordinator owns queue order, immutable cell identity, leases,
retries, result publication, and GUI state. The Mac initiates an authenticated
HTTPS connection, registers a structured preflight, claims only cells accepted
by its pool, re-resolves each cell against the same reviewed checkout, and
uploads only these generated outputs:

```text
artifacts/result.fidb
artifacts/result.fidbf
artifacts/cell-seal.json
```

The coordinator stages each upload beneath the leased job, checks worker and
lease ownership, resolved-cell identity, declared sizes and SHA-256 values,
seal contents, and timing, then publishes the attempt atomically beneath
`artifacts/runs/`. SQLite contains runtime state and artifact references; a
remote worker never opens or copies the coordinator database.

Apple SDKs, Xcode applications, signing material, Apple credentials, build
trees, and the worker token never enter Git or the Linux host. This boundary is
deliberate. Apple publishes the controlling terms in the
[Xcode and Apple SDKs Agreement](https://www.apple.com/legal/sla/docs/xcode.pdf).
Operators remain responsible for the agreement applicable to their use.

The external TOML is declarative and accepts no command. It fixes the worker
pool, platform, architecture, route, target, probe adapter, declared language
capabilities, deployment target, required tools, metadata contract, and
worker-specific resource floor. Registration, leases, uploads, and GUI state
are language-neutral. The current `apple-xcode` adapter probes C and C++
because those are the capabilities declared by this first definition; later
languages require their own reviewed profile and fixed probe implementation.

## Intended operator flow

After the Mac has a local checkout at the same reviewed revision:

```sh
./scripts/workers/macos-preflight.sh
./scripts/workers/macos-run.sh --until-drained
```

The preflight is safe to run at any time. It checks host identity and fixed
tool probes, performs C and C++17 ARM64 Mach-O smoke compilation in a temporary
directory, and reports structured metadata. It does not enqueue or claim work.

The run wrapper requires a private environment file based on
`operations/macos-worker.env.example`. It refuses to start unless preflight
passes, and the coordinator refuses registration unless its credential is
authorized for `macos-native`. If the Mac is offline, its jobs remain queued
while other pools continue.

The first production use must remain a single zlib canary. Inspect the returned
seal, Xcode/SDK identity, object format, FIDB/FIDBF files, timings, and retained
bytes before adding more libraries or worker processes. Remote artifacts use
idempotent 8 MiB chunks with a final whole-file digest and a 4 GiB per-artifact
safety ceiling; the extended-run review must retain sufficient space for
partial staging plus atomic publication.
