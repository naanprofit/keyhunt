#!/usr/bin/env bash
# Benchmark: same ptable, vary bloom size/quality, compare keys/second.
#
# Setup: N=0x400000000 (2^34), K=128
#   bsgs_m   = 16,777,216  (16M baby steps)
#   bsgs_m3  = 16,384      (ptable entries = fixed ~229 KB)
#   L1 shard entries = 65,536/shard
#
# Bloom configurations tested:
#   A) Small (default 1e-6 error) - optimal for entry count
#   B) Large (--mapped-size overrides to a bigger shard)
#   C) Saturated (all-0xFF shards, simulating the 0.98 error bug)
#
# The search range is intentionally huge so it never completes;
# we just read the KPS stats line and kill after SEARCH_SEC seconds.

set -euo pipefail
KEYHUNT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/keyhunt"
[[ -x "$KEYHUNT" ]] || { echo "keyhunt binary not found; run make first" >&2; exit 1; }

N="0x400000000"
K=128
THREADS=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4)
THREADS=$(( THREADS > 8 ? 8 : THREADS ))
SEARCH_SEC=45
TARGET_FILE="$(dirname "${BASH_SOURCE[0]}")/1to63_65.txt"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

PTABLE="$WORKDIR/bptable.bin"
BLOOMDIR="$WORKDIR/bloom"
mkdir -p "$BLOOMDIR"

echo "=== keyhunt BSGS bloom-size vs KPS benchmark ==="
echo "N=$N  K=$K  threads=$THREADS  search_duration=${SEARCH_SEC}s"
echo ""

# ----------------------------------------------------------------
# Helper: extract the last KPS reading from a log file.
# Handles both "~400 Gkeys/s" and plain "0 keys/s" formats.
# ----------------------------------------------------------------
extract_kps() {
    local log="$1"
    # Lines look like: "[+] Total 12345 keys in N seconds: ~X Gkeys/s (Y keys/s)"
    local last
    last=$(grep 'keys in [0-9]' "$log" 2>/dev/null | tail -1)
    if [[ -z "$last" ]]; then
        echo "(no stats in window)"
        return
    fi
    # Extract raw keys/s value from the parenthesised number, then format it.
    local raw
    raw=$(echo "$last" | grep -oE '\(([0-9]+) keys/s\)' | grep -oE '[0-9]+') || true
    if [[ -z "$raw" ]]; then
        raw=$(echo "$last" | grep -oE ': [0-9]+ keys/s' | grep -oE '[0-9]+') || raw="0"
    fi
    python3 -c "
r=$raw
if   r >= 1e12: print('%.1f Tkeys/s' % (r/1e12))
elif r >= 1e9:  print('%.1f Gkeys/s' % (r/1e9))
elif r >= 1e6:  print('%.1f Mkeys/s' % (r/1e6))
else:           print('%d keys/s' % r)
"
}

# ----------------------------------------------------------------
# Step 1: Build bloom + ptable (run A - default/small bloom)
# ----------------------------------------------------------------
echo "--- Step 1: Building bloom + ptable (default 1e-6 error) ---"
BUILD_LOG="$WORKDIR/build.log"
"$KEYHUNT" -m bsgs \
    -f "$TARGET_FILE" \
    -n "$N" -k $K \
    -r 0:ffffffffffffff \
    -t $THREADS \
    --mapped --mapped-dir "$BLOOMDIR" \
    --bloom-file "$BLOOMDIR/bloom.dat" \
    --mapped-error 1e-6 \
    --ptable "$PTABLE" \
    -s 5 -q \
    --bsgs-build-only 2>&1 | tee "$BUILD_LOG" | grep -E 'bP points|bloom|ptable|layer|Error' | grep -v 'Loading'
echo ""

# Count shard files so we know layout
L1_SHARDS=$(ls "$BLOOMDIR"/*.layer1-*.dat 2>/dev/null | wc -l || echo 0)
L1_SIZE=$(ls -la "$BLOOMDIR"/*.layer1-000.dat 2>/dev/null | awk '{print $5}' || echo 0)
echo "[info] L1 shards: $L1_SHARDS  shard[0] size: $(numfmt --to=iec $L1_SIZE 2>/dev/null || echo "${L1_SIZE}B")"
echo "[info] Ptable: $(ls -lh "$PTABLE" 2>/dev/null | awk '{print $5}' || echo 'N/A')"
echo ""

# ----------------------------------------------------------------
# Run A: Search with default bloom
# ----------------------------------------------------------------
echo "--- Run A: Search with default bloom (1e-6 error, $(numfmt --to=iec $L1_SIZE 2>/dev/null || echo "${L1_SIZE}B")/shard) ---"
LOG_A="$WORKDIR/runA.log"
timeout ${SEARCH_SEC}s "$KEYHUNT" -m bsgs \
    -f "$TARGET_FILE" \
    -n "$N" -k $K \
    -r 0:ffffffffffffff \
    -t $THREADS \
    --mapped --mapped-dir "$BLOOMDIR" \
    --bloom-file "$BLOOMDIR/bloom.dat" \
    --load-bloom \
    --ptable "$PTABLE" --load-ptable \
    -s 5 -q > "$LOG_A" 2>&1 || true
KPS_A=$(extract_kps "$LOG_A")
echo "  KPS: $KPS_A"
echo ""

# ----------------------------------------------------------------
# Build larger bloom (4x bigger per shard via --mapped-size)
# ----------------------------------------------------------------
echo "--- Step 2: Building larger bloom (4x shard size via --mapped-size) ---"
BLOOMDIR2="$WORKDIR/bloom_large"
mkdir -p "$BLOOMDIR2"
# L1_SIZE * 4 rounded to MB
LARGE_BYTES=$(( (L1_SIZE * 4 / 1048576 + 1) * 1048576 ))
LARGE_SZ_M=$(( LARGE_BYTES / 1048576 ))
echo "[info] Target shard size: ${LARGE_SZ_M}M (${LARGE_BYTES}B)"
BUILD_LOG2="$WORKDIR/build_large.log"
"$KEYHUNT" -m bsgs \
    -f "$TARGET_FILE" \
    -n "$N" -k $K \
    -r 0:ffffffffffffff \
    -t $THREADS \
    --mapped --mapped-dir "$BLOOMDIR2" \
    --bloom-file "$BLOOMDIR2/bloom.dat" \
    --mapped-size "${LARGE_SZ_M}M" \
    --ptable "$PTABLE" --load-ptable \
    -s 5 -q \
    --bsgs-build-only 2>&1 | tee "$BUILD_LOG2" | grep -E 'bP points|bloom|ptable|layer|Error' | grep -v 'Loading'
echo ""

L1_SIZE2=$(ls -la "$BLOOMDIR2"/*.layer1-000.dat 2>/dev/null | awk '{print $5}' || echo 0)
echo "[info] Large L1 shard[0] size: $(numfmt --to=iec $L1_SIZE2 2>/dev/null || echo "${L1_SIZE2}B")"
echo ""

# ----------------------------------------------------------------
# Run B: Search with larger bloom
# ----------------------------------------------------------------
echo "--- Run B: Search with larger bloom (${LARGE_SZ_M}M/shard) ---"
LOG_B="$WORKDIR/runB.log"
timeout ${SEARCH_SEC}s "$KEYHUNT" -m bsgs \
    -f "$TARGET_FILE" \
    -n "$N" -k $K \
    -r 0:ffffffffffffff \
    -t $THREADS \
    --mapped --mapped-dir "$BLOOMDIR2" \
    --bloom-file "$BLOOMDIR2/bloom.dat" \
    --load-bloom \
    --ptable "$PTABLE" --load-ptable \
    -s 5 -q > "$LOG_B" 2>&1 || true
KPS_B=$(extract_kps "$LOG_B")
echo "  KPS: $KPS_B"
echo ""

# ----------------------------------------------------------------
# Run C: Saturated bloom (replace shards with all-0xFF of same size)
# ----------------------------------------------------------------
echo "--- Step 3: Replacing default bloom shards with all-0xFF (simulating --mapped-error 0.98 bug) ---"
BLOOMDIR3="$WORKDIR/bloom_sat"
cp -r "$BLOOMDIR" "$BLOOMDIR3"
for f in "$BLOOMDIR3"/*.dat; do
    sz=$(wc -c < "$f")
    python3 -c "import sys; sys.stdout.buffer.write(b'\xff' * $sz)" > "$f"
done
echo "[info] All bloom shards replaced with 0xFF (saturated)"
echo ""

echo "--- Run C: Search with saturated bloom (all-0xFF, simulating bad --mapped-error) ---"
LOG_C="$WORKDIR/runC.log"
timeout ${SEARCH_SEC}s "$KEYHUNT" -m bsgs \
    -f "$TARGET_FILE" \
    -n "$N" -k $K \
    -r 0:ffffffffffffff \
    -t $THREADS \
    --mapped --mapped-dir "$BLOOMDIR3" \
    --bloom-file "$BLOOMDIR3/bloom.dat" \
    --load-bloom \
    --ptable "$PTABLE" --load-ptable \
    -s 5 -q > "$LOG_C" 2>&1 || true
KPS_C=$(extract_kps "$LOG_C")
echo "  KPS: $KPS_C"
echo ""

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo "========== RESULTS SUMMARY =========="
echo "Configuration           | KPS"
echo "------------------------|----------------------------"
echo "A) Default bloom (1e-6) | $KPS_A"
echo "B) Large bloom (${LARGE_SZ_M}M/sh) | $KPS_B"
echo "C) Saturated bloom (0xFF)| $KPS_C"
echo ""
echo "N=$N K=$K ptable=FIXED search=${SEARCH_SEC}s threads=$THREADS"
echo "====================================="
