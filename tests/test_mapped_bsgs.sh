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

BLOOM="$TMPDIR/bloom.dat"
PTABLE="$TMPDIR/bptable.dat"

# Build mapped bloom + ptable and search a tiny range containing known keys
./keyhunt -m bsgs \
  -r 1:ffffff \
  -f tests/1to63_65.txt \
  --mapped "$BLOOM" \
  --mapped-size 1M \
  --bloom-bytes 1M \
  --tmpdir "$TMPDIR" \
  --ptable "$PTABLE" \
  --ptable-cache \
  -k 1 \
  -n 0x100000 \
  -t 1 \
  -q \
  -s 1 | tee "$TMPDIR/output.txt"

grep -q "privkey 1" "$TMPDIR/output.txt"

grep -q "ptable: LOADING" "$TMPDIR/output.txt" || true

# Re-run in load-only mode to ensure mapped artifacts stay usable
./keyhunt -m bsgs \
  -r 1:ffffff \
  -f tests/1to63_65.txt \
  --mapped "$BLOOM" \
  --mapped-size 1M \
  --bloom-bytes 1M \
  --tmpdir "$TMPDIR" \
  --ptable "$PTABLE" \
  --ptable-cache \
  --load-ptable \
  --load-bloom \
  -k 1 \
  -n 0x100000 \
  -t 1 \
  -q \
  -s 1 | tee "$TMPDIR/output_load.txt"

grep -q "privkey 1" "$TMPDIR/output_load.txt"
