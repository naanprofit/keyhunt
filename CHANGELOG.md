# naanprofit fork CHANGELOG

The entries below this line cover work on the `naanprofit/keyhunt` fork.
Upstream alberto-bsd entries continue below the divider.

## 2026-04-24 -- BSGSD parity port + bug fixes + shared client lib (this branch)

Three commits on `codex/fix-bloom-saturation-and-error-rate-validation`:

### Commit A -- BSGSD: parity port (`1756b37`)
`bsgsd.cpp` had drifted ~12 features behind `keyhunt.cpp`.  This commit
ports the missing features so calling out to BSGSD produces identical
results to running keyhunt directly.

- New flag `--bsgs-endo=off|keyhunt|glv12` -- 3-lane angrygiant +
  `bsgs_secondcheck_endo` + `bsgs_thirdcheck_endo`, with identical
  recovery semantics to keyhunt.
- New flag `--honest-counter` -- emits `X-Steps` and per-lane
  `X-Lane-N-{Probes,Hits,Recov}` HTTP headers so callers can audit
  actual scalar coverage and bloom-filter dynamics separately.
- New flag `--gpu-bloom` -- reserved for GPU bloom prefilter; flag
  surface only in this commit, full hookup follows.
- New flag `--public` -- convenience alias for `-i 0.0.0.0`.
- `lambda` / `lambda2` / `beta` / `beta2` globals populated in `main()`
  from the same hex constants `keyhunt.cpp` uses.
- `OriginalPointsBSGS_endo[2]` (singular here -- BSGSD is one-target-
  per-request, unlike keyhunt's vector) populated in `client_handler`
  when `--bsgs-endo!=off`.
- Per-lane diagnostic counters (probes/hits/recovers, all atomic)
  matching keyhunt for cross-tool parity.
- `bsgs_live_steps` / `bsgs_steps_total` atomics fed by 3 `fetch_add`
  sites in the inner bucket loop, so the status path can report honest
  keys/sec.

**Honest finding (kept the wiring, but documented the truth):** on
narrow puzzle ranges `--bsgs-endo` is **~2x SLOWER** than `off` because
3 lanes do 3x probe work but the orbit images fall outside `[from,to]`
so the extra work is pure overhead.  Only useful for whole-keyspace
scans or kangaroo-style port.  See
`research/BSGS_ENDOMORPHISM_WIRING_2026_04_24.md`.

### Commit B -- BSGSD: bug fixes (`3a8866f`)
Six BSGSD bugs that have been latent since earlier releases; new traffic
from keyhunt callers + magic_wand fill jobs would have made any of them
concrete.

1. **Server-side single-flight mutex** (`single_search_mutex`).  Docs
   always claimed "one client at a time" but the code did not enforce
   it.  Two simultaneous `client_handler` threads would race on
   `BSGS_CURRENT`, `n_range_start/end`, `OriginalPointsBSGS`,
   `bsgs_found`, `BSGSkeyfound`, and the new endo lane counters.  Now
   serialized -- a second client blocks until the first finishes.
2. **Hostname binding via `getaddrinfo()`**.  Previously `-i fozzie`
   (or any non-numeric IP) silently fell back to 0.0.0.0 because
   `inet_pton()` only accepts IPv4 literals.  Now hostnames resolve
   correctly; only truly unresolvable input falls back, with a clear
   warning.
3. **Banner accuracy**.  Now reports BOTH the user-supplied label AND
   the resolved IP, e.g. `[+] Listening in fozzie (192.168.200.51):8080`,
   so users can verify hostname resolution actually worked.
4. **SIGINT / SIGTERM graceful shutdown**.  Adds `shutdown_signal_handler`
   that flips a flag and `shutdown()`s the listening socket.  The
   `accept()` loop now checks the flag and handles `EINTR` cleanly, so
   Ctrl-C exits without leaving sockets dangling.
5. **Misleading "Closing connection" log replaced**.  The old line
   fired immediately after `pthread_create`, BEFORE the detached thread
   actually finished its search; the connection was not closed at that
   point.  Now logs `[+] Dispatched <ip>:<port> to worker thread` at
   handoff time.
6. **`BSGSD.md` docs corrected**.  Said default IP was 127.0.0.1; actual
   default has been 0.0.0.0 since this branch.  Documents new flags
   `--bsgs-endo`, `--honest-counter`, `--gpu-bloom`, `--public`, and the
   single-flight serialization behavior.  File CRLF endings normalized
   to LF.

### Commit C -- libbsgsd_client.a + tests + Makefile target
New shared client library `lib/bsgsd_client.{h,cpp}` usable by keyhunt,
magic_wand, and any future tool that wants pool-aware BSGSD access.

- TCP single-line and HTTP POST JSON transports with timeout-aware
  connect/recv on top of POSIX sockets and `getaddrinfo`.
- `Pool` class with round-robin and fan-out dispatch, per-host health
  tracking, retry-on-failure.
- HTTP response parser that extracts `X-Elapsed-Seconds`, `X-Steps`,
  `X-BSGS-Endo`, `X-GPU-Bloom`, and per-lane diagnostic headers when
  the daemon is started with `--honest-counter`.
- New Makefile targets:
  - `make libbsgsd_client.a` -- builds the static lib (pure C++17 +
    POSIX sockets, no third-party deps).
  - `make clean_lib` -- removes the static lib and intermediate `.o`s.

## 2026-04-24 (earlier on this branch) -- bloom and counter fixes

Pre-BSGSD work on the same branch (commits `b5458ee` and `d0e9a5d`,
inherited as the working baseline for the BSGSD port):

- **Fix bloom saturation handling** (`b5458ee`).
  - Validate `--mapped-error` / `--bloom-bytes` arguments instead of
    silently using bogus values.
  - Fix the static-override bug where a previous override would leak
    into a subsequent run.
  - Add saturation warnings when the bloom load factor is high enough
    to materially degrade the false-positive rate.
- **Fix bloom k-mismatch causing ~1000x KPS regression on bloom load**
  (`d0e9a5d`).  Previously a saved bloom file's `k` (number of hash
  functions) could mismatch the run-time configuration, silently
  producing the wrong probe pattern and tanking throughput.  Now
  validated at load and rejected if mismatched.
- **Wire GLV endomorphism into BSGS angrygiant + honest counter**
  (`fb2362e`).  This commit landed earlier on the branch -- the BSGSD
  parity port is the back-port of these features into bsgsd.cpp.

## Inherited from earlier `naanprofit/keyhunt` branches

These fixes were merged into this branch via prior PRs and are
documented here for completeness so users upgrading from upstream
alberto-bsd see the full picture:

- **Bloom file creation and merging** (PRs #82 / #83, ea4ed4a / 4a2e396).
  Worker shards reuse existing blooms when available; duplicate shards
  are no longer created when reuse is requested.
- **Bus error during data loading** (PR #81, edcb365).  Skip rebuild
  when loading mapped blooms instead of touching their pages, which
  caused SIGBUS on read-only mounts.
- **Worker0 directory isolation** (PR #80, b1d2f68).  When multiple
  workers run in parallel, worker0 now uses a dedicated directory so
  it does not collide with the merged bloom output.
- **Bus error during execution** (PR #79, a76a7b4).  Fix BSGS merge
  sizing to use the correct entry count when the merged bloom spans
  shards of different sizes.
- **Worker output directory structure** (PRs #76, #77, #78).
  - Allow bloom merge to fall back to worker metadata directories.
  - Prevent nested mapped bloom paths for worker shards.
  - Retry bloom merge with default shard names when a custom name was
    set but the named shard was missing.
- **Worker output directory paths** (PRs #73, #74).
  - Add `--bsgs-build-only` for BSGS workers.
  - Fix worker outdir override for sharded builds.
- **Sharded merge tests + bloom merge sizing alignment** (PR #72,
  c534a07).
- **Sharded BSGS workflow documentation** (PR #71, f4e181e).
- **BSGS merge merge pipeline + meta loader** (PR #70, 96173c9 /
  8985120).  CLI flags and meta-file format for bloom merge.
- **Worker slice handling and metadata** (PR #69, b7f34b5 / 045a1d9).
- **Bloom shard IO scoped to worker outputs** (PR #68, 70c600d).
- **Mapped bloom configuration improvements** (various, 67cf71e /
  41bd34f / e685b24 / be9e034 / 7803af1 / a735c76 / 6fd35a9).
  - Configurable mmap prefetch controls and IO logging.
  - Clamp mapped chunk configuration.
  - Improve mapped bloom placement and planning.
  - Fix BSGS target loading.
  - Add mapped bloom readonly option plumbing.
  - Handle duplicate BSGS matches and add regression test.
  - Fix BSGS binary search bounds.
  - Protect existing ptables unless rebuild requested.
  - Harden load-only ptable handling and CLI parsing.
  - Make bsgsd bloom generation lock-free.
  - Speed up bloom table generation.
  - Fix BSGS stride for GGSB.

---

# Upstream (alberto-bsd) CHANGELOG

# Version 0.2.230519 Satoshi Quest
- Speed x2 in BSGS mode for main version

# Version 0.2.230507 Satoshi Quest
- fixed some variables names
- fixed bug in addvanity (realloc problem with dirty memory)
- Added option -6 to skip SHA256 checksum when you read the files (Improved startup process)
- Added warning when you Endomorphism and BSGS, THEY DON'T WORK together!
- Legacy version for ARM processor and other systems
- remove pub2rmd

# Version 0.2.230430 Satoshi Quest
- fixed typos in README
- Speed counter fixed for Compress search without endomorphism check https://github.com/albertobsd/keyhunt/tree/development#Speeds

# Version 0.2.230428 Satoshi Quest
- Merge of address and rmd160 speeds
- Added option for endomorphism
- Added SAVE bloom filter and table option for adddress, rmd160, minikeys and xpoint
- Improved Makefile options
- Updated random function to use the Linux RNG with the function getrandom

# Version 0.2.211117 SSE Trick or treat ¡Beta!
- Minikeys new sequential generator and x2 times more speed
- third bloom filter check for bsgs 20% less memory usage

# Version 0.2.211031 Trick or treat ¡Beta!
- Minikeys improvements in speed
- Test to try solve the https://github.com/albertobsd/keyhunt/issues/139 issue

# Version 0.2.211026 Chocolate ¡Beta!
- Solved https://github.com/albertobsd/keyhunt/issues/130
- Minikeys new generator improvements in speed

# Version 0.2.211024 Chocolate ¡Beta!
- Ethereum support
- Double speed for rmd160 mode
- Minikeys mode support
- Stride option

# Version 0.2.211018 Chocolate ¡Beta!
- Solved some bugs: https://github.com/albertobsd/keyhunt/issues/122 https://github.com/albertobsd/keyhunt/issues/111
- Files are going to be updated automatillyca 
-- from keyhunt_bsgs_3_*.blm  to keyhunt_bsgs_4*.blm 
-- from keyhunt_bsgs_1_*.blm  to keyhunt_bsgs_5*.blm 
-- the program will notify you when time to delete the old files

# Version 0.2.211012 Chocolate ¡Beta!
- Fixed the slow bP table generation.
-- This fix make obsolete the files keyhunt_bsgs_0_*.blm 
-- please delete those files, please do:

```
rm keyhunt_bsgs_0_*.blm 
```

- Added multi vanitysearch for address mode


# Version 0.2.211007 Chocolate ¡Beta!
- BSGS improvements:
--  10x more Speed
--  new submodes for BSGS, secuential (default), backward, both, random and dance
--  automatic file generation for bloom filter file and bPtable file.
--  Good bye to bPfile.
- Memory check periodically for bloom filters and bP Table

# Version 0.1.20210420 secp256k1
- Solved Issues 49, 50 51
  See:
  https://github.com/albertobsd/keyhunt/issues/51
  https://github.com/albertobsd/keyhunt/issues/50
  https://github.com/albertobsd/keyhunt/issues/49
- Solved Issues 56 https://github.com/albertobsd/keyhunt/issues/56
- Added mutex to the bloom filter for multithread writing

# Version 0.1.20210412 secp256k1
- Full migration from libgmp to secp256k1
- Change the way for keygeneration for modes xpoint, address, and rmd160
- Improve performance for xpoint mode, now is ten times faster
- Change N variable type for modes address,rmd160 and xpoint, from uint32_t to uint64_t
- Added method pub2rmd to search publickeys of the puzzles and other legacy address (Compress publickeys only)

# Version 0.1.20210331
- Small changes to be compiled with mingw on Windows
- Changed sort functions and binary search for modes address/rmd160/xpoint, now those modes can load MAX 2^64 items
- xpoint input file now can contains Comments after the line of data
- from this version all furthers developments will be in the branch `development`

# Version 0.1.20210328
- Added a progress counter (this solve bug https://github.com/albertobsd/keyhunt/issues/18 )
- Added multithread for precalculating bP items or reading then from file
- Fixed the code to avoid warnings (this solve the issue https://github.com/albertobsd/keyhunt/issues/19)

# Version 0.1.20210322
- Added xxhash for bloomfilter this hash have better performance than murmurhash2. And it is 64 bits hash :)
- We reduce the number of items of the bPtable in ram using a second bloom filter, thanks @iceland2k14
- The ram saved space is around 80%, so we can use a bigger K value, around 4 or 5 times bigger than previous version

# Version 0.1.20210320 K*BSGS
- Solved little error with compress and uncompress new param -l. See https://github.com/albertobsd/keyhunt/issues/17
- function bsgs optimized to use a little less RAM (not related with Pfile)
- Again removed some compile warnings. See https://github.com/albertobsd/keyhunt/issues/16

# Version 0.1.20210311 K*BSGS
- Added mode rmd160, this method works two times faster than Address method. This mode can search all the altcoins


# Version 0.1.20210311 K*BSGS
- Solved some bug when the publickeys in the input file was invalid but the program keeps running with 0 publickeys
- Now publickeys can be compressed, not only uncompressed

# Version 0.1.20210306 K*BSGS
- Added K factor for BSGS
- Added bPfile.c to generate a precalculated file
- Remove unused files about keccak and sha3
- Change Bloom filter limits and % of error from 0.001 to 0.00001 in bloomfilter.

# Version 0.1.20210112 BSGS
- Added mode BSGS this work with a file with uncompressed keys
- Updated  bloom filter to allow More items

# Version 0.1.20201228
- Change Quicksort to Introsort, this solve some edge cases of quicksort.
- Introsort is avaible to keyhunt and hexcharstoraw. worst case. O(N log N).
- Aling of some output text

# Version 0.1.20201223
- Added new tool hexcharstoraw to create a raw binary file for xpoint from a text-hexadecimal file
- Added option -w to work with raw binary file, this file contains xpoint in binary format fixed to 32 bytes

# Version 0.1.20201222
- Fixed some ugly bug in the searchbinary function thanks to Ujang
- Added to stdout the vanitykeys found with -v option

# Version 0.1.20201221
- Fixed search by xpoint.
- Added -e option to skip the sort process whe the file is already sorted.
- Fixed debugcount when upto N is less than debugcount.
- Changed "-R upto" to "-R" and added "-n upto" option.

# Version 0.1.20201218
- Minor bugs fixed.

# Version 0.1.20201217
- First Release
- Thanks to all CryptoHunters to make this code possible
