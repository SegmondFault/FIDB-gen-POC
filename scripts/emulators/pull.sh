#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_directory/../.." && pwd)

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [PROVIDER]" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  exec uv run --project "$project_root" fidb-poc emulator pull \
    --project-root "$project_root" --provider "$1"
fi

exec uv run --project "$project_root" fidb-poc emulator pull \
  --project-root "$project_root"
