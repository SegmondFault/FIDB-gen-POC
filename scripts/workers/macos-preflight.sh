#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: the Apple worker preflight must run on macOS" >&2
    exit 1
fi
if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is required to run the reviewed project environment" >&2
    exit 1
fi

exec uv run --project "$project_root" fidb-poc external-worker preflight \
    --project-root "$project_root" \
    --definition macos-arm64-apple-clang
