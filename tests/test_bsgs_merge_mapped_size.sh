#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
cd "$repo_root"

TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

build_common=(
  -m bsgs
  -r 1:ffffff
  -f tests/1to63_65.txt
  --mapped
  --mapped-size 1M
  --mapped-dir "$TMPDIR"
  --tmpdir "$TMPDIR"
  --ptable "$TMPDIR/bptable.tbl"
  --worker-outdir "$TMPDIR"
  --bsgs-build-only
  -k 1
  -n 0x400000
  -t 1
  -q
  -s 1
)

# Build two worker slices with custom mapped sizing.
./keyhunt "${build_common[@]}" --worker-id 0 --worker-total 2
./keyhunt "${build_common[@]}" --worker-id 1 --worker-total 2

# Collect metadata for merging.
cp "$TMPDIR/worker1/bptable.tbl.worker1.meta" "$TMPDIR/"

merge_cmd=(
  ./keyhunt
  -m bsgs
  -f tests/1to63_65.txt
  -r 1:ffffff
  -n 0x400000
  --mapped-dir "$TMPDIR"
  --ptable "$TMPDIR/bptable.tbl"
  --bsgs-merge-from "$TMPDIR/bptable.tbl.worker*.meta"
  --bsgs-merge-only
  -q
)

"${merge_cmd[@]}"

worker_size=$(stat -c %s "$TMPDIR/worker1/bloom.layer1-000.dat")
merged_size=$(stat -c %s "$TMPDIR/bloom.layer1-000.dat")

if [[ "$worker_size" != "$merged_size" ]]; then
  echo "[E] merged bloom shard size mismatch"
  exit 1
fi

echo "[+] mapped merge sizing test passed"
