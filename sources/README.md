# Pinned library source packs

Source packs freeze release archives before build recipes are written or
qualified. They keep source selection reproducible without implying that every
library already works across the compiler-width matrix.

`c-top10-v1.toml` remains the immutable source authority used by the completed
C10 campaign. `c-top20-v1.toml` preserves those pins through C20.
`c-top30-v1.toml` extends the same ranking snapshot with zlib, libidn2, libffi,
ICU, libxml2, libgcrypt, GnuTLS, libuv, OpenJPEG and Opus at ranks 21–30.
Every row records the study rank, release, official release page,
immutable archive URL, observed byte count, SHA-256 digest, archive filename,
and expected top-level source directory. The tracked TOML is portable; archive
bytes are kept in the ignored local cache.

Inspect the complete pack without downloading anything:

```sh
uv run fidb-poc source status c-top10-v1 --project-root .
uv run fidb-poc source status c-top20-v1 --project-root .
uv run fidb-poc source status c-top30-v1 --project-root .
```

Pull every missing archive sequentially into the locked, content-addressed
cache and verify both its digest and byte count:

```sh
uv run fidb-poc source pull c-top10-v1 --project-root .
```

Use repeated `--id` arguments to inspect or pull a subset:

```sh
uv run fidb-poc source pull c-top10-v1 --project-root . \
  --id sqlite \
  --id xz
```

An archive already downloaded into local staging can cross the same immutable
cache boundary without a second network transfer:

```sh
uv run fidb-poc source import c-top30-v1 --project-root . \
  --id opus --file /path/to/opus-1.6.1.tar.gz
```

`source import` resolves the expected digest and byte count from the reviewed
pack, rejects an unlisted identity, verifies the local file, and publishes it
with the same lock, quarantine and atomic rename contract as `source pull`.
It does not extract or execute the archive.

The managed bytes live under `var/fidb-sources/downloads/`, named by SHA-256.
That directory is deliberately ignored by Git. Invalid cached bytes are
quarantined by the same acquisition boundary used for toolchain packs; partial
downloads are not published into the cache.

Source acquisition is deliberately separate from execution. `source pull`
does not extract archives, run upstream build logic, create recipes, compile,
or invoke Ghidra. Moving a source into the build matrix still requires a
reviewed `fidb-recipe/v3` recipe, a supported fixed adapter, route-specific
qualification, and an explicitly armed campaign.

To extend the pack, add a new `[[source]]` row or create a separately versioned
pack. Never use a floating `latest` URL: choose an explicit stable release,
download it from the upstream project, record the exact byte count and SHA-256,
and run `source status` after acquisition. Changing any pin changes the
catalogue digest reported by the CLI.

## Complete C80 research-candidate acquisition

The 276-row four-source N80 list is a research frontier, not a reviewed list
of reusable C libraries. Its source acquisition is therefore separate from
the immutable `c-top10`/`c-top20`/`c-top30` build packs. Prefetching a candidate
does not mark it screened, recipe-ready, qualified or queueable.

The process has four explicit boundaries:

1. `refresh` downloads the configured official registry indexes into
   `var/fidb-sources/metadata/`, addresses each snapshot by SHA-256 and writes
   a TOML snapshot registry.
2. `resolve` consumes only those frozen snapshots. It writes the complete,
   reviewable lock at `sources/locks/c80-four-source-n80-v1.toml`.
3. `status` compares every pin with the content-addressed local cache without
   downloading or changing anything.
4. `pull` downloads only locked HTTPS payloads, verifies every SHA-256 before
   publication and updates a per-lock TOML acquisition registry after every
   completed or failed transfer.

Run the lifecycle explicitly:

```sh
.venv/bin/fidb-poc source acquisition refresh \
  c80-four-source-n80-v1 --project-root .
.venv/bin/fidb-poc source acquisition resolve \
  c80-four-source-n80-v1 --project-root .
.venv/bin/fidb-poc source acquisition status \
  c80-four-source-n80-v1 --project-root .
.venv/bin/fidb-poc source acquisition pull \
  c80-four-source-n80-v1 --project-root .
```

The tracked policy is
`sources/acquisition/c80-four-source-n80-v1.toml`. It fixes the candidate CSV
digest, resolver order, declared aliases, safety limits and default download
concurrency. The tracked lock records the exact registry snapshot digests,
mapping kind, package identity, release, URL, checksum and any upstream byte
count. Re-running `resolve` against the same snapshots must reproduce the same
lock bytes.

The local pull registry is
`var/fidb-sources/acquisition/c80-four-source-n80-v1.<LOCK_SHA256>.toml`. Each
`[[source]]` row records candidate rank, resolver and registry identity,
version, URL, checksum, observed bytes, cache path, outcome, first observation,
download time where known and latest verification time. `[[failure]]` rows are
retained with their timestamp and error class. Including the lock digest in
the filename preserves the history when a future metadata refresh creates a
new lock.

The current lock resolves 252 candidates through checksum-bearing Homebrew
source archives and 23 through Debian's checksum-and-size-bearing source
index. Rank 62, `opengl`, remains visibly unresolved: OpenGL is an API/system
interface rather than one canonical source distribution. Candidate screening
must select a concrete implementation such as Mesa if that row is retained;
the resolver must not make that scientific choice implicitly.

`pull` defaults to eight bounded network workers. A different transfer-only
concurrency can be selected with `--workers`; this does not extract sources or
start compilation/Ghidra. Re-running it is resumable because verified cache
objects are skipped and corrupt objects fail the cache integrity boundary.
