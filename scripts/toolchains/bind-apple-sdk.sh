#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_directory/../.." && pwd)

if [ "$#" -ne 6 ]; then
  echo "usage: $0 SDK_PACKAGE SHA256 BYTES XCODE_VERSION SDK_VERSION DEPLOYMENT_TARGET" >&2
  exit 2
fi

exec uv run --project "$project_root" fidb-poc toolchain input bind apple-macos-sdk \
  --project-root "$project_root" \
  --path "$1" \
  --sha256 "$2" \
  --bytes "$3" \
  --metadata "xcode_version=$4" \
  --metadata "sdk_version=$5" \
  --metadata "deployment_target=$6" \
  --metadata "sha256=$2" \
  --metadata "bytes=$3"
