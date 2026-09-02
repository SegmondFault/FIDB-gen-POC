#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
environment_file=${FIDB_MACOS_WORKER_ENV:-"$HOME/.config/fidb-factory/macos-worker.env"}

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: the Apple worker must run on macOS" >&2
    exit 1
fi
if [ ! -f "$environment_file" ]; then
    echo "error: worker environment file not found: $environment_file" >&2
    exit 1
fi
if [ "$(stat -f '%Lp' "$environment_file")" != "600" ]; then
    echo "error: worker environment file must have mode 0600" >&2
    exit 1
fi

set -a
# This file is private, operator-owned configuration; never commit it.
. "$environment_file"
set +a

: "${FIDB_REMOTE_COORDINATOR:?missing FIDB_REMOTE_COORDINATOR}"
: "${FIDB_REMOTE_WORKER_ID:?missing FIDB_REMOTE_WORKER_ID}"
: "${FIDB_REMOTE_WORKER_TOKEN:?missing FIDB_REMOTE_WORKER_TOKEN}"

exec uv run --project "$project_root" fidb-poc remote-worker run \
    --project-root "$project_root" \
    --queue plans/priority-queue.toml \
    --coordinator "$FIDB_REMOTE_COORDINATOR" \
    --worker-id "$FIDB_REMOTE_WORKER_ID" \
    --token-env FIDB_REMOTE_WORKER_TOKEN \
    --pool macos-native \
    --external-toolchain macos-arm64-apple-clang \
    "$@"
