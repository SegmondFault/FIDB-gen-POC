# Toolchain qualification evidence

This directory contains committed, machine-readable observations from explicit
toolchain qualification runs. A snapshot records the reviewed source revision,
catalog and profile digests, host class, route-material identities, result
digests, object formats, and measured storage. It does not make another clone
qualified.

Current readiness remains host-local and must be re-established with:

```sh
./scripts/toolchains/status.sh c-top10-linux
./scripts/toolchains/qualify.sh c-top10-linux
./scripts/toolchains/status.sh c-top10-linux
```

The full qualification records and smoke objects remain beneath the ignored
`var/fidb-toolchains/qualified/` tree. This prevents a clone from inheriting a
claim about tools it does not possess. The committed snapshot provides an
auditable comparison target: a repeated run can compare its profile,
route-material, and qualification-record digests without copying the original
machine's runtime state.

The 2026-09-02 `reference-host` snapshot covers the nine Linux-managed routes in
`c-top10-linux`. Native Apple Clang was deliberately deferred and has no entry
in the qualified route list.
