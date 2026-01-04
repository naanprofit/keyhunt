#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/keyhunt"
if [[ ! -x "$BIN" ]]; then
  echo "keyhunt binary not found at $BIN; build the project first" >&2
  exit 1
fi
out="$($BIN -h 2>&1)"
required=("--mapped" "--mapped-plan" "--mapped-populate" "--mapped-willneed" \
  "--bloom-bytes" "--ptable" "--ptable-prealloc" "--load-ptable" "--io-verbose")
for flag in "${required[@]}"; do
  if ! grep -q "$flag" <<<"$out"; then
    echo "missing flag in help: $flag" >&2
    exit 1
  fi
done
