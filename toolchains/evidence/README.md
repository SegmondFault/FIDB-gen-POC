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

`c-compiler-width-v1-reference-host-2026-09-02.toml` records the first complete
29-route compiler-generation qualification. Its grouped compiler rows preserve
the target multiplicity, while digest-set hashes bind the complete ordered
route-material and qualification-record sets. Full smoke objects and records
remain in the host-local qualification store.

`c-android-width-v1-reference-host-2026-09-02.toml` records eight qualified Android
routes: four ABIs at NDK r27d/Clang 18 and NDK r29/Clang 21, all at API 21.
The two shared NDK packs passed fixed C/C++ compilation and ELF
class/endianness/machine validation. This is toolchain evidence only; it is not
evidence that OpenSSL or another library batch ran on those routes.
