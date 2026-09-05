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
