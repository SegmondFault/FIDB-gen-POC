# Reviewed native recipes

The TOML files in this directory bind a canonical library release to a pinned
source archive, exact source-identity markers, a fixed adapter name, and the
static archives retained for analysis. They are declarative authority: recipe
files cannot contain commands, flags, scripts, or arbitrary environment data.
Executable behavior lives in `src/fidb_poc/adapters.py` and is covered by unit
tests.

The current top-ten set is:

| Recipe | Fixed adapter | Retained archive(s) |
| --- | --- | --- |
| OpenSSL 3.5.8 | `openssl-configure` | `libcrypto.a`, `libssl.a` |
| SQLite 3.53.4 | `sqlite-autoconf` | `libsqlite3.a` |
| XZ 5.8.3 | `xz-autoconf` | `liblzma.a` |
| Zstandard 1.5.7 | `zstd-make` | `libzstd.a` |
| PCRE2 10.48 | `pcre2-autoconf` | `libpcre2-8.a` |
| LZ4 1.10.0 | `lz4-make` | `liblz4.a` |
| gettext 1.0 | `gettext-autoconf` | `libintl.a` |
| nghttp2 1.70.0 | `nghttp2-autoconf` | `libnghttp2.a` |
| Readline 8.3 | `readline-autoconf` | `libreadline.a`, `libhistory.a` |
| GMP 6.3.0 | `gmp-autoconf` | `libgmp.a` |

The specialized adapter names are intentional. They allow each upstream
project to have a reviewed, minimal static-library target without making
configure arguments or make targets caller-controlled. Target and compiler
identity remain separate route axes; the adapter maps a route to its reviewed
GNU host tuple and always receives treatment flags from the worker.

There are three narrow upstream accommodations worth preserving during future
updates:

- gettext's `intl` library must use the directory's recursive `all` target so
  its private gnulib archive is built first. Its configure-time C++ probe uses
  the adjacent cross-toolchain driver even though the retained library is C.
- GMP's `all` target must run its host-side table/header generators before the
  static library can be built.
- Readline 8.3 leaves an otherwise-unused POSIX `winsize` tag undefined under
  MinGW. Only `terminal.o` and `rltty.o` receive the fixed opaque-tag mapping;
  Unix and Android builds are untouched.

## Qualification boundary

On 2026-09-03 the nine newly added recipes completed 144 compilation-only
canaries from pristine copies of the checksum-verified source archives:

- all nine recipes on one route for every distinct current target class:
  eight Linux architectures, four Android ABIs, and Windows x86-64; and
- all nine on the oldest current generation edges: GCC 12 x86-64,
  llvm-mingw/Clang 15 x86-64, and Android NDK r27d AArch64.

Each canary produced exactly the declared static archive set. These checks did
not run Ghidra, every compiler generation, or every treatment, and they did not
arm or materialize `batch-020`. Full object-format validation, analysis, and
hash comparison remain work for the disarmed campaign.

To review pins without executing a build:

```sh
uv run fidb-poc source status c-top10-v1 --project-root .
uv run fidb-poc compile-width-batch batch-020 --project-root .
```

When updating a release, change the source pack and matching recipe together,
review upstream build changes, rerun adapter tests and the same target/generation
canaries, then inspect the batch projection before considering materialization.
