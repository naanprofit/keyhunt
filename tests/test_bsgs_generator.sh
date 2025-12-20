#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

short_file="$tmpdir/short_test.txt"
head -n 10 tests/1to63_65.txt > "$short_file"

ptable="$tmpdir/ptable"
log="$tmpdir/run.log"

set +e
timeout 60s ./keyhunt -m bsgs -r 0:ffffff -f "$short_file" \
  -t 2 -q -n 0x400000 -k 2 --tmpdir "$tmpdir" \
  --bsgs-block-count 1 --bloom-bytes 512K --force-ptable-rebuild -s 10 \
  --ptable "$ptable" >"$log" 2>&1
status=$?
set -e

if [[ $status -ne 0 ]]; then
  cat "$log"
  exit $status
fi

grep -q "privkey 1" "$log"
grep -q "privkey 2" "$log"

echo "[+] generator search regression passed"
