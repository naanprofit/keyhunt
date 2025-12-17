#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/keyhunt"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ ! -x "$BIN" ]]; then
  echo "keyhunt binary not found at $BIN; build the project first"
  exit 1
fi

read -r EXPECTED_BYTES < <(python - <<'PY'
import ctypes, math

n = 1 << 20
k_factor = 1
m = int(math.isqrt(n)) * k_factor
m2 = (m + 31) // 32
m3 = (m2 + 31) // 32

class BX(ctypes.Structure):
    _fields_ = [
        ("value", ctypes.c_uint8 * 6),
        ("index", ctypes.c_uint64),
    ]

entry_size = ctypes.sizeof(BX)
print(m3 * entry_size)
PY
)

ptable="$TMPDIR/ptable.bin"
python - "$ptable" "$EXPECTED_BYTES" <<'PY'
import os, secrets, sys
path = sys.argv[1]
size = int(sys.argv[2])
with open(path, "wb") as f:
    f.write(secrets.token_bytes(size))
PY

orig_sha=$(sha256sum "$ptable" | awk '{print $1}')
orig_mtime=$(stat -c %Y "$ptable")

load_cmd=(timeout 5 "$BIN" -m bsgs -f "$ROOT/tests/120.txt" -r 1:1000000 \
  -n 0x100000 -k 1 --tmpdir "$TMPDIR" --ptable "$ptable" --load-ptable \
  -q -t 1 -s 1 --bloom-bytes 1024)

if ! "${load_cmd[@]}"; then
  status=$?
  if [[ $status -ne 124 ]]; then
    echo "keyhunt load-only run failed with status $status"
    exit 1
  fi
fi

new_sha=$(sha256sum "$ptable" | awk '{print $1}')
new_mtime=$(stat -c %Y "$ptable")

if [[ "$orig_sha" != "$new_sha" ]]; then
  echo "ptable contents changed during load-only run"
  exit 1
fi

if [[ "$orig_mtime" != "$new_mtime" ]]; then
  echo "ptable mtime changed during load-only run"
  exit 1
fi

rm -f "$ptable"
if "${load_cmd[@]}"; then
  echo "missing ptable load-only run unexpectedly succeeded"
  exit 1
fi

if [[ $? -eq 124 ]]; then
  echo "missing ptable load-only run hung"
  exit 1
fi

if [[ -e "$ptable" ]]; then
  echo "ptable was recreated unexpectedly"
  exit 1
fi
