# Emulator providers

The emulator interface is host-neutral. A worker may use a reviewed managed
pack, an explicitly configured external installation, or no emulator at all.
The scheduler must use reported capabilities rather than assume that the
coordinator host can execute a target.

The first managed provider is the standard static QEMU user-mode suite for an
x86-64 Linux host. Its Arch package is only a signed, immutable distribution
container: the project does not invoke `pacman`, install globally, register
`binfmt_misc`, or require an Arch-derived host. Prepared files remain ignored
under `var/fidb-emulators/`.

```sh
uv run fidb-poc emulator status --project-root .
uv run fidb-poc emulator pull --project-root .
uv run fidb-poc emulator status --project-root . --probe
```

To use an existing installation, copy `local.example.toml` to the ignored
`local.toml`, set its root and list the exact executable for every permitted
target. Status records resolved paths, versions and executable SHA-256 values.
Recipes never supply emulator paths or arguments.

Managed providers are selected only when their declared host OS and
architecture match. Further Linux, macOS and Windows host providers can be
added without changing target identities. An unsupported host can still run
the control plane and dispatch execution to a compatible worker.
