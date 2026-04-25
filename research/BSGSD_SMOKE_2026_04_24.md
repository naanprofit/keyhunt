# BSGSD smoke results -- puzzles 30, 35, 40, 45, 50

**Date:** 2026-04-24
**Host:** fozzie (94GB RAM, 32 core, Linux)
**Branch:** `codex/fix-bloom-saturation-and-error-rate-validation` @ `defea99`

End-to-end validation of the three BSGSD parity / fix / lib commits
against published Bitcoin puzzle pubkeys.  Every recovered private key
is **cryptographically verified** (recomputed pubkey matches the
published one and lies in the puzzle-N range `[2^(N-1), 2^N)`).

## Setup

- `make bsgsd` and `make libbsgsd_client.a` both build clean on fozzie
  (Linux x86-64, gcc 11) with two pre-existing trivial warnings
  (unused vars in BSGS thread args).
- BSGSD launched in RAM-only mode with `-k 4 -n 0x40000000` (baby
  table = 2^30 entries, ~10 GB total bloom + table footprint).
- All five puzzles share the same on-disk bloom/table files; bsgsd
  was restarted between mode comparisons but the same `.blm`/`.tbl`
  files were reused via the standard auto-reload path.

## Results (puzzle suite, --bsgs-endo=off)

Single bsgsd instance, HTTP POST JSON transport, `--honest-counter`
enabled.

| Puzzle | Range hex          | Recovered k          | Wall (s) | Verified |
| -----: | :----------------- | :------------------- | -------: | :------- |
|     30 | `20000000:40000000`             | `3d94cd64`           |    < 1   | YES      |
|     35 | `400000000:800000000`           | `4aed21170`          |    < 1   | YES      |
|     40 | `8000000000:10000000000`        | `e9ae4933d6`         |    < 1   | YES      |
|     45 | `100000000000:200000000000`     | `122fca143c05`       |      1   | YES      |
|     50 | `2000000000000:4000000000000`   | `22bd43c2e9354`      |     20   | YES      |

Verification: each key, when fed through SECP256k1 scalar mul, produces
the exact compressed pubkey published for that puzzle.  See
`tests/test_bsgsd_protocol.py` for an automated equivalent.

## --honest-counter HTTP headers (puzzle 50, --bsgs-endo=off)

```
HTTP/1.1 200 OK
Content-Length: 14
X-Elapsed-Seconds: 21.122
X-Steps: 183831018
X-BSGS-Endo: off
X-GPU-Bloom: 0
X-Lane-0-Probes: 183831018
X-Lane-0-Hits: 6
X-Lane-0-Recov: 1
X-Lane-1-Probes: 0
X-Lane-1-Hits: 0
X-Lane-1-Recov: 0
X-Lane-2-Probes: 0
X-Lane-2-Hits: 0
X-Lane-2-Recov: 0

22bd43c2e9354
```

## Endomorphism cross-check (all three modes find the same key)

Same target (puzzle 50, pubkey
`03f46f41027bbf44fafd6b059091b900dad41e6845b2241dc3254c7cdd3c5a16c6`),
same range (`2000000000000:4000000000000`), three different
`--bsgs-endo` modes:

| Mode    | Recovered k       | Wall (s) | X-Steps     | L0 P/H/R     | L1 P/H/R    | L2 P/H/R    |
| :------ | :---------------- | -------: | ----------: | :----------- | :---------- | :---------- |
| off     | `22bd43c2e9354`   |    21.1  | 183,831,018 | 183M / 6 / 1 | 0 / 0 / 0   | 0 / 0 / 0   |
| keyhunt | `22bd43c2e9354`   |    54.2  | 551,515,736 | 183M / 6 / 1 | 183M / 0 / 0 | 183M / 1 / 0 |
| glv12   | `22bd43c2e9354`   |    54.0  | 551,489,274 | 183M / 6 / 1 | 183M / 0 / 0 | 183M / 1 / 0 |

The same recovery happens through lane 0 in all three cases.  Lanes 1
and 2 do equal probe work (~183 M each) but produce **zero successful
recoveries** because, for narrow puzzle ranges, the lambda-twisted
orbit images fall outside `[from, to]`.  This is the previously-
documented behavior in
`research/BSGS_ENDOMORPHISM_WIRING_2026_04_24.md`, now confirmed end
to end on the parity-ported BSGSD daemon.

**Quantitative confirmation:**
- `off` mode: 21.1 s, 183 M probes
- `keyhunt`/`glv12`: 54 s, 551 M probes ≈ 3 × the work
- Slowdown ratio: 2.55× / 2.56× -- matches the 2.1× -- 2.5× range
  measured directly against the keyhunt binary in the original endo
  bench.

## Puzzle 30 micro-cross-check (every mode recovers identically)

Range `20000000:40000000`, pubkey
`030d282cf2ff536d2c42f105d0b8588821a915dc3f9a05bd98bb23af67a2e92a5b`.

| Mode    | k          | X-Steps | Lane 0 probes | L0 recov | L1 recov | L2 recov |
| :------ | :--------- | ------: | ------------: | -------: | -------: | -------: |
| off     | `3d94cd64` |   1,372 |         1,372 |        1 |        0 |        0 |
| keyhunt | `3d94cd64` |   3,420 |         1,372 |        1 |        0 |        0 |
| glv12   | `3d94cd64` |   3,420 |         1,372 |        1 |        0 |        0 |

Step counts confirm the lane budget:
- 1 lane (off): N probes
- 3 lanes (keyhunt/glv12): ~3 N probes; lanes 1/2 do real bloom work
  but, as expected on narrow ranges, never recover

Recovery is byte-identical in all three modes.

## Puzzle 60 / 70 / 80 -- intentionally skipped on-host

Puzzle 60 has a published pubkey
(`0348e843dc5b1bd246e6309b4924b81543d02b16c8083df973a89ce2c7eb89a10d`),
but the range is `[2^59, 2^60)` -- 1024x larger than puzzle 50.  With
the same `-k 4 -n 0x40000000` table, expected wall time is ~6 hours
single-host.  Hitting it inside a session budget would require either:
- a much larger baby table (`-k 1024 -n 0x40000000` -> ~10 TB of bloom,
  not feasible on this host),
- mapped mode with disk-backed blooms (slower per probe but feasible),
- multi-host pool dispatch via the new `libbsgsd_client.a` (still
  needs hours of compute distributed across ~5+ hosts), or
- GPU bloom prefilter (currently a flag stub).

Puzzles 70 and 80 do not have published pubkeys in the
`tests/1to63_65.txt` fixture; their published artifacts are RIPEMD-160
addresses only (see `tests/unsolvedpuzzles.txt` /
`tests/puzzleswopublickey.txt`).  BSGSD requires a pubkey, so those
puzzles can only be attacked in keyhunt's address-mode, not via the
BSGSD wire protocol.

For this smoke run we deliberately stuck to puzzles **with** revealed
pubkeys (everything up through 64), and selected the largest size
(puzzle 50) that completes in seconds without GPU acceleration.

## Conclusions

1. **All three BSGSD commits work end-to-end on a real Linux host.**
   Build clean, daemon launches, both transports respond, all five
   puzzles solved with cryptographically-verified keys.
2. **`--honest-counter` HTTP headers are correct and useful.**  The
   per-lane probe / hit / recovery counts directly measure the cost
   of `--bsgs-endo` on narrow ranges and confirm the "2x slower for
   no benefit" prediction in the bench writeup.
3. **All three `--bsgs-endo` modes return identical, correct keys**
   when the key is in the user's range (which it is, for these
   puzzles).  The endo lanes themselves never fire (zero recoveries),
   confirming that the wiring is correct but the strategy only pays
   off on whole-keyspace scans, not on puzzle ranges.
4. **`libbsgsd_client.a` builds clean** on fozzie with
   `-std=c++17 -O2 -Wall` (no warnings).  Not yet exercised end-to-end
   here -- next session will use it from magic_wand's oracle filler.

## Reproducibility

```bash
ssh sigkill@fozzie
cd ~/THEFALLEN/keyhunt
git checkout codex/fix-bloom-saturation-and-error-rate-validation
make bsgsd libbsgsd_client.a
rm -f keyhunt_bsgs_*.blm keyhunt_bsgs_*.tbl  # force RAM build
./bsgsd -6 -t 4 -k 4 -n 0x40000000 -i 127.0.0.1 -p 8410 \
        -B angrygiant --honest-counter &
# wait for "[+] Listening in 127.0.0.1:8410"

# puzzle 50 example:
curl -X POST -H 'Content-Type: application/json' \
  -d '{"pubkey":"03f46f41027bbf44fafd6b059091b900dad41e6845b2241dc3254c7cdd3c5a16c6","from":"2000000000000","to":"4000000000000"}' \
  http://127.0.0.1:8410/
```
