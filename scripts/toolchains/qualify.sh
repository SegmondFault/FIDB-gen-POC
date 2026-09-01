#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_directory/../.." && pwd)
profile=${1:-c-top10-linux}

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [PROFILE]" >&2
  exit 2
fi

exec uv run --project "$project_root" fidb-poc toolchain profile qualify "$profile" --project-root "$project_root"
