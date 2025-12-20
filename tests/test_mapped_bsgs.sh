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

ptable_hash=$(sha256sum "$PTABLE" | awk '{print $1}')
ptable_mtime=$(stat -c %Y "$PTABLE")

# Run without --load-ptable to ensure we auto-detect and never truncate existing tables
./keyhunt -m bsgs \
  -r 1:ffffff \
  -f tests/1to63_65.txt \
  --mapped "$BLOOM" \
  --mapped-size 1M \
  --bloom-bytes 1M \
  --tmpdir "$TMPDIR" \
  --ptable "$PTABLE" \
  --ptable-cache \
  --load-bloom \
  -k 1 \
  -n 0x100000 \
  -t 1 \
  -q \
  -s 1 | tee "$TMPDIR/output_auto.txt"

grep -q "existing file .* enabling --load-ptable" "$TMPDIR/output_auto.txt"
grep -q "privkey 1" "$TMPDIR/output_auto.txt"

ptable_hash_after=$(sha256sum "$PTABLE" | awk '{print $1}')
ptable_mtime_after=$(stat -c %Y "$PTABLE")

if [[ "$ptable_hash" != "$ptable_hash_after" || "$ptable_mtime" != "$ptable_mtime_after" ]]; then
  echo "[E] ptable was modified when it should have been reused"
  exit 1
fi
