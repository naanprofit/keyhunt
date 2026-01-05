#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BIN="$ROOT_DIR/keyhunt"

if [[ ! -x "$BIN" ]]; then
  echo "keyhunt binary not found at $BIN; build the project first" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

pushd "$WORKDIR" >/dev/null

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
  --mapped
  --mapped-chunks 1
  --force-ptable-rebuild
)

run_worker() {
  local wid=$1
  local wdir="workers/w$(printf "%03d" "$wid")"
  mkdir -p "$wdir"
  timeout 45s "$BIN" "${common_args[@]}" \
    --worker-total "$workers" \
    --worker-id "$wid" \
    --worker-outdir ./workers \
    --mapped-dir "./${wdir}" \
    --bloom-file "./${wdir}/bloom.dat" \
    --ptable "./${wdir}/ptable.tbl" \
    --bsgs-build-only \
    >"$WORKDIR/worker_${wid}.log" 2>&1
}

for wid in $(seq 0 $((workers - 1))); do
  run_worker "$wid"
done

for wid in $(seq 0 $((workers - 1))); do
  wdir="$WORKDIR/workers/w$(printf "%03d" "$wid")"
  expected="$wdir/bloom.dat.layer1-000.dat"
  nested="$wdir/workers/w$(printf "%03d" "$wid")/bloom.dat.layer1-000.dat"
  if [[ ! -f "$expected" ]]; then
    echo "expected bloom shard missing at $expected" >&2
    exit 1
  fi
  if [[ -f "$nested" ]]; then
    echo "unexpected nested bloom path created at $nested" >&2
    exit 1
  fi
done

popd >/dev/null

echo "[+] worker-relative mapped bloom paths stay in expected directories"
