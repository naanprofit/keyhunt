#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BIN="$ROOT_DIR/keyhunt"

if [[ ! -x "$BIN" ]]; then
  echo "keyhunt binary not found at $BIN; build the project first" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

shards_dir="$TMPDIR/shards"
mkdir -p "$shards_dir"
workers=2

common_args=(
  -m bsgs
  -r 1:ffffff
  -f "$ROOT_DIR/tests/1to63_65.txt"
  -k 1
  -n 0x400000
  -q
  -s 1
  -t 1
  --bsgs-block-count 1
  --mapped "$shards_dir/bloom.dat"
  --mapped-chunks 2
)

ptable_base="$shards_dir/bptable.tbl"
ptable_merged="$shards_dir/bptable_merged.tbl"

run_worker() {
  local wid=$1
  local outdir=$2
  local mapped_dir=$3
  local ptable_path=$4
  local worker_tmp="$TMPDIR/worker_${wid}_$(basename "$outdir")"
  mkdir -p "$worker_tmp"
  timeout 90s "$BIN" "${common_args[@]}" \
    --worker-total "$workers" \
    --worker-id "$wid" \
    --worker-outdir "$outdir" \
    --mapped-dir "$mapped_dir" \
    --ptable "$ptable_path" \
    --tmpdir "$worker_tmp" \
    --bsgs-build-only \
    --force-ptable-rebuild \
    >"$TMPDIR/worker_${wid}_$(basename "$outdir").log" 2>&1
}

for wid in $(seq 0 $((workers - 1))); do
  run_worker "$wid" "$shards_dir" "$shards_dir" "$ptable_base"
done

for m in "$shards_dir"/worker*/bptable.tbl.worker*.meta; do
  if [[ -f "$m" ]]; then
    cp "$m" "$shards_dir"/
  fi
done

meta_glob="$shards_dir/bptable.tbl.worker*.meta"

if ! ls $meta_glob >/dev/null 2>&1; then
  echo "worker metadata missing after shard generation" >&2
  exit 1
fi

# Make shards read-only to ensure merge uses mapped read-only loads for inputs.
chmod -w "$shards_dir"/worker*/bloom*.dat* "$shards_dir"/bloom*.dat* "$shards_dir"/worker*/bptable.tbl "$shards_dir"/bptable.tbl

merge_outdir="$shards_dir"
merge_log="$TMPDIR/merge.log"

timeout 90s "$BIN" "${common_args[@]}" \
  --worker-total "$workers" \
  --worker-outdir "$merge_outdir" \
  --mapped-dir "$merge_outdir" \
  --ptable "$ptable_merged" \
  --bsgs-merge-from "$meta_glob" \
  --bsgs-merge-only \
  >"$merge_log" 2>&1

# Assert canonical bloom shards were produced with the expected chunking.
[[ -f "$merge_outdir/bloom.layer1-000.dat.0" && -f "$merge_outdir/bloom.layer1-000.dat.1" ]]
[[ -f "$merge_outdir/bloom2.layer2-000.dat.0" && -f "$merge_outdir/bloom2.layer2-000.dat.1" ]]
[[ -f "$merge_outdir/bloom3.layer3-000.dat.0" && -f "$merge_outdir/bloom3.layer3-000.dat.1" ]]

# Validate merged ptable ordering and checksum against a re-sorted union of worker slices.
merged_md5=$(python - "$meta_glob" "$ptable_merged" <<'PY'
import glob, hashlib, os, struct, sys

meta_paths = sorted(glob.glob(sys.argv[1]))
ptable_path = sys.argv[2]

entries = []
for meta in meta_paths:
    kv = {}
    with open(meta, 'r') as fh:
        for line in fh:
            line = line.strip()
            if not line or '=' not in line:
                continue
            k, v = line.split('=', 1)
            kv[k] = v
    slice_path = kv['ptable_path']
    if not os.path.isabs(slice_path):
        slice_path = os.path.join(os.path.dirname(meta), slice_path)
    slice_path = os.path.normpath(slice_path)
    start = int(kv['ptable_slice_start'])
    length = int(kv['ptable_slice_len'])
    with open(slice_path, 'rb') as fh:
        data = fh.read()
    stride = len(data) // max(length, 1)
    if stride * length != len(data) or stride < 14:
        raise SystemExit(f"unexpected ptable slice sizing for {slice_path} (len={len(data)} stride={stride})")
    for i in range(length):
        off = i * stride
        val = data[off:off+6]
        idx = int.from_bytes(data[off+6:off+14], 'little')
        padding = data[off+14:off+stride]
        entries.append((val, idx, padding))

if not entries:
    raise SystemExit("no entries aggregated from worker slices")

sorted_entries = sorted(entries, key=lambda e: e[0])
buf = b''.join(val + idx.to_bytes(8, 'little') + pad for val, idx, pad in sorted_entries)

with open(ptable_path, 'rb') as fh:
    merged = fh.read()

expected_md5 = hashlib.md5(buf).hexdigest()
actual_md5 = hashlib.md5(merged).hexdigest()

if expected_md5 != actual_md5:
    raise SystemExit(f"md5 mismatch: expected {expected_md5} got {actual_md5}")

if merged != buf:
    raise SystemExit("merged ptable ordering does not match sorted worker union")

print(actual_md5)
PY
)

if [[ -z "$merged_md5" ]]; then
  echo "failed to compute merged ptable md5" >&2
  exit 1
fi

echo "[+] merged ptable md5: $merged_md5"

run_negative_merge() {
  local meta_dir=$1
  local expect_pattern=$2
  local label=$3
  local dest="$TMPDIR/${label}_out"
  rm -rf "$dest"
  mkdir -p "$dest"
  set +e
  timeout 30s "$BIN" "${common_args[@]}" \
    --worker-total "$workers" \
    --worker-outdir "$dest" \
    --mapped-dir "$dest" \
    --mapped "$dest/bloom.dat" \
    --ptable "$dest/bptable.tbl" \
    --bsgs-merge-from "$meta_dir" \
    --bsgs-merge-only \
    >"$TMPDIR/${label}.log" 2>&1
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    echo "${label} merge unexpectedly succeeded" >&2
    exit 1
  fi
  if ! grep -q "$expect_pattern" "$TMPDIR/${label}.log"; then
    echo "${label} merge did not emit expected failure pattern '$expect_pattern'" >&2
    cat "$TMPDIR/${label}.log"
    exit 1
  fi
}

dup_meta_dir="$TMPDIR/dup_meta"
mkdir -p "$dup_meta_dir"
cp $meta_glob "$dup_meta_dir/"
cp "$shards_dir/bptable.tbl.worker0.meta" "$dup_meta_dir/duplicate.meta"
run_negative_merge "$dup_meta_dir" "Duplicate worker id" "duplicate_workers"

missing_meta_dir="$TMPDIR/missing_meta"
mkdir -p "$missing_meta_dir"
cp "$shards_dir/bptable.tbl.worker0.meta" "$missing_meta_dir/"
run_negative_merge "$missing_meta_dir" "Missing metadata for worker" "missing_worker"

mismatch_meta_dir="$TMPDIR/mismatch_meta"
mkdir -p "$mismatch_meta_dir"
cp $meta_glob "$mismatch_meta_dir/"
perl -pi -e 's/mapped_chunks=2/mapped_chunks=3/' "$mismatch_meta_dir"/*.meta
run_negative_merge "$mismatch_meta_dir" "mapped-chunks mismatch" "param_mismatch"

echo "[+] BSGS merge shard tests passed"

# Repeat the merge with worker directories already named w000/w001 to ensure
# existing worker-style subdirectories are respected instead of forcing workerX.
wstyle_dir="$TMPDIR/shards_wstyle"
mkdir -p "$wstyle_dir/w000" "$wstyle_dir/w001"
ptable_base_w="$wstyle_dir/ptable.tbl"
ptable_merged_w="$wstyle_dir/ptable_merged.tbl"

for wid in $(seq 0 $((workers - 1))); do
  run_worker "$wid" "$wstyle_dir" "$wstyle_dir" "$ptable_base_w"
done

meta_glob_w="$wstyle_dir/w00*/ptable.tbl.worker*.meta"

if ! ls $meta_glob_w >/dev/null 2>&1; then
  echo "worker metadata missing for w-style layout" >&2
  exit 1
fi

timeout 90s "$BIN" "${common_args[@]}" \
  --worker-total "$workers" \
  --worker-outdir "$wstyle_dir" \
  --mapped-dir "$wstyle_dir" \
  --ptable "$ptable_merged_w" \
  --bsgs-merge-from "$meta_glob_w" \
  --bsgs-merge-only \
  >"$TMPDIR/merge_wstyle.log" 2>&1

[[ -f "$wstyle_dir/bloom.layer1-000.dat.0" && -f "$wstyle_dir/bloom.layer1-000.dat.1" ]]
[[ -f "$wstyle_dir/bloom2.layer2-000.dat.0" && -f "$wstyle_dir/bloom2.layer2-000.dat.1" ]]
[[ -f "$wstyle_dir/bloom3.layer3-000.dat.0" && -f "$wstyle_dir/bloom3.layer3-000.dat.1" ]]

echo "[+] BSGS merge shard tests (w-style dirs) passed"
