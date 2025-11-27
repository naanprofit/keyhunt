#!/usr/bin/env python3
import argparse
import http.client
import json
import socket
import threading
import queue
import time
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple

# ------------- Data structures -------------

@dataclass
class ChunkTask:
    start: int
    end: int
    attempt: int = 1

@dataclass
class MatchResult:
    pubkey: str
    start_hex: str
    end_hex: str
    privkey: str
    found_pubkey: Optional[str]
    address: Optional[str]
    host: str
    port: int
    raw_response: str
    status_code: Optional[int] = None

@dataclass
class TimeoutRecord:
    pubkey: str
    start_hex: str
    end_hex: str
    attempts: int


# ------------- Helpers -------------

def hex_to_int(h: str) -> int:
    h = h.strip()
    if h.lower().startswith("0x"):
        h = h[2:]
    return int(h, 16)


def parse_range(range_str: str) -> Tuple[int, int]:
    parts = range_str.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid range '{range_str}', expected from:to")
    start = hex_to_int(parts[0])
    end = hex_to_int(parts[1])
    if start > end:
        raise ValueError(f"Range start > end: {range_str}")
    return start, end


def chunk_range(start: int, end: int, chunk_size: int):
    cur = start
    while cur <= end:
        chunk_end = min(cur + chunk_size - 1, end)
        yield cur, chunk_end
        cur = chunk_end + 1


def load_pubkeys(path: str) -> List[str]:
    keys = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) == 1:
                keys.append(parts[0])
            else:
                keys.append(parts[-1])
    return keys


# ------------- bsgsd client (raw TCP or HTTP) -------------

class BsgsdClient:
    def __init__(self, host: str, port: int, timeout_sec: float, use_http: bool = False, http_path: str = "/search", verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout_sec
        self.use_http = use_http
        self.http_path = http_path
        self.verbose = verbose

    def _log(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    def query(self, pubkey_hex: str, start_hex: str, end_hex: str) -> Tuple[Optional[int], str]:
        """
        Talk to bsgsd using raw TCP or HTTP JSON.

        Raw protocol:
            <pubkey_hex> <from_hex>:<to_hex>\n

        HTTP protocol:
            POST <path> with JSON body {"pubkey":..., "from":..., "to":...}
        """
        if self.use_http:
            body = json.dumps({"pubkey": pubkey_hex, "from": start_hex, "to": end_hex})
            headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
            self._log(f"[DEBUG][HTTP] -> {self.host}:{self.port}{self.http_path} body={body}")
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            try:
                conn.request("POST", self.http_path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read().decode("ascii", errors="ignore")
                status = resp.status
            finally:
                conn.close()
            self._log(f"[DEBUG][HTTP] <- {self.host}:{self.port} status={status} body={repr(data)}")
            return status, data

        line = f"{pubkey_hex} {start_hex}:{end_hex}\n"
        data = line.encode("ascii")
        self._log(f"[DEBUG] -> {self.host}:{self.port} '{line.strip()}'")

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(data)
            chunks: List[bytes] = []
            while True:
                try:
                    buf = sock.recv(4096)
                except socket.timeout:
                    raise TimeoutError(f"socket recv timeout after {self.timeout}s")
                if not buf:
                    break
                chunks.append(buf)

        resp = b"".join(chunks).decode("ascii", errors="ignore")
        self._log(f"[DEBUG] <- {self.host}:{self.port} response: {repr(resp)}")
        return None, resp


# ------------- Response parsing -------------

_hex64_re = re.compile(r"\b([0-9a-fA-F]{64})\b")
_compressed_pub_re = re.compile(r"\b(02|03)[0-9a-fA-F]{64}\b")
_base58_addr_re = re.compile(r"\b[13][1-9A-HJ-NP-Za-km-z]{25,40}\b")


def parse_bsgsd_response(resp: str):
    """
    Try to extract privkey, pubkey, address.

    Return:
        (privkey_hex, pubkey_hex or None, address or None) or None if no match.
    """
    text = resp.strip()
    if not text:
        return None

    lower = text.lower()
    if "404" in lower and "private key" not in lower and "hit" not in lower:
        return None

    m_priv = _hex64_re.search(text)
    if not m_priv:
        return None

    privkey = m_priv.group(1)
    m_pub = _compressed_pub_re.search(text)
    pubkey = m_pub.group(0) if m_pub else None
    m_addr = _base58_addr_re.search(text)
    addr = m_addr.group(0) if m_addr else None

    return privkey, pubkey, addr


# ------------- Worker threads -------------

def worker_loop(
    worker_id: int,
    host: str,
    port: int,
    pubkey: str,
    task_queue: "queue.Queue[ChunkTask]",
    match_queue: "queue.Queue[MatchResult]",
    timeout_queue: "queue.Queue[TimeoutRecord]",
    stop_event: threading.Event,
    producer_done: threading.Event,
    timeout_sec: float,
    max_retries: int,
    retry_timeouts: bool,
    verbose: bool,
    use_http: bool,
    http_path: str,
):
    client = BsgsdClient(host, port, timeout_sec, use_http=use_http, http_path=http_path, verbose=verbose)

    def log(msg: str):
        prefix = f"[{host}:{port} | worker {worker_id}]"
        print(f"{prefix} {msg}", flush=True)

    while not stop_event.is_set():
        try:
            task: ChunkTask = task_queue.get(timeout=1.0)
        except queue.Empty:
            if stop_event.is_set() or producer_done.is_set():
                break
            continue

        if stop_event.is_set():
            task_queue.task_done()
            break

        start_hex = f"{task.start:x}"
        end_hex = f"{task.end:x}"

        log(f"processing chunk {start_hex}:{end_hex} (attempt {task.attempt})")

        try:
            status_code, resp = client.query(pubkey, start_hex, end_hex)
        except TimeoutError as e:
            log(f"request {start_hex}:{end_hex} timed out: {e}")
            if retry_timeouts and task.attempt < max_retries:
                task_queue.put(ChunkTask(task.start, task.end, task.attempt + 1))
                log(f"re-queued timed-out chunk {start_hex}:{end_hex} (attempt {task.attempt}/{max_retries})")
            else:
                timeout_queue.put(TimeoutRecord(pubkey=pubkey, start_hex=start_hex, end_hex=end_hex, attempts=task.attempt))
                log(f"giving up on chunk {start_hex}:{end_hex} after {task.attempt} attempts")
            task_queue.task_done()
            continue
        except OSError as e:
            log(f"connection error for chunk {start_hex}:{end_hex}: {e}")
            if retry_timeouts and task.attempt < max_retries:
                task_queue.put(ChunkTask(task.start, task.end, task.attempt + 1))
                log(f"re-queued errored chunk {start_hex}:{end_hex} (attempt {task.attempt}/{max_retries})")
            else:
                timeout_queue.put(TimeoutRecord(pubkey=pubkey, start_hex=start_hex, end_hex=end_hex, attempts=task.attempt))
                log(f"giving up on errored chunk {start_hex}:{end_hex} after {task.attempt} attempts")
            task_queue.task_done()
            continue

        if use_http and status_code is not None:
            if status_code == 404:
                task_queue.task_done()
                continue
            if status_code >= 400:
                log(f"HTTP error {status_code} for chunk {start_hex}:{end_hex}: {resp.strip()}")
                task_queue.task_done()
                continue

        parsed = parse_bsgsd_response(resp)
        if parsed is None:
            task_queue.task_done()
            continue

        privkey, found_pub, addr = parsed
        log(f"*** MATCH FOUND *** priv={privkey} addr={addr} pub={found_pub}")
        match_queue.put(
            MatchResult(
                pubkey=pubkey,
                start_hex=start_hex,
                end_hex=end_hex,
                privkey=privkey,
                found_pubkey=found_pub,
                address=addr,
                host=host,
                port=port,
                raw_response=resp,
                status_code=status_code,
            )
        )
        stop_event.set()
        task_queue.task_done()
        break


# ------------- Main orchestration -------------

def scan_for_pubkey(
    pubkey: str,
    global_start: int,
    global_end: int,
    chunk_size: int,
    hosts: List[str],
    port: int,
    timeout_sec: float,
    max_retries: int,
    retry_timeouts: bool,
    matches_file,
    timed_out_records: List[TimeoutRecord],
    verbose: bool,
    use_http: bool,
    http_path: str,
    queue_max: int = 1000,
) -> Optional[MatchResult]:
    print(f"\n[INFO] === Target pubkey: {pubkey} ===", flush=True)
    print(f"[INFO] Global range {global_start:x}:{global_end:x}", flush=True)
    print(f"[INFO] Chunk size up to {chunk_size:x}", flush=True)
    print(f"[INFO] Hosts: {', '.join(h+':'+str(port) for h in hosts)}", flush=True)
    if use_http:
        print(f"[INFO] HTTP mode enabled (path: {http_path})", flush=True)

    task_queue: "queue.Queue[ChunkTask]" = queue.Queue(maxsize=queue_max)
    match_queue: "queue.Queue[MatchResult]" = queue.Queue()
    timeout_queue: "queue.Queue[TimeoutRecord]" = queue.Queue()
    stop_event = threading.Event()
    producer_done = threading.Event()

    def producer():
        try:
            for start, end in chunk_range(global_start, global_end, chunk_size):
                while not stop_event.is_set():
                    try:
                        task_queue.put(ChunkTask(start=start, end=end, attempt=1), timeout=1.0)
                        break
                    except queue.Full:
                        if stop_event.is_set():
                            return
                        continue
        finally:
            producer_done.set()

    producer_thread = threading.Thread(target=producer, daemon=True)
    producer_thread.start()

    threads: List[threading.Thread] = []
    for idx, host in enumerate(hosts):
        t = threading.Thread(
            target=worker_loop,
            kwargs=dict(
                worker_id=idx,
                host=host,
                port=port,
                pubkey=pubkey,
                task_queue=task_queue,
                match_queue=match_queue,
                timeout_queue=timeout_queue,
                stop_event=stop_event,
                producer_done=producer_done,
                timeout_sec=timeout_sec,
                max_retries=max_retries,
                retry_timeouts=retry_timeouts,
                verbose=verbose,
                use_http=use_http,
                http_path=http_path,
            ),
            daemon=True,
        )
        t.start()
        print(f"[INFO] Worker started for {host}:{port}", flush=True)
        threads.append(t)

    found: Optional[MatchResult] = None

    while True:
        try:
            found = match_queue.get(timeout=1.0)
            break
        except queue.Empty:
            if stop_event.is_set() and task_queue.empty() and producer_done.is_set():
                break
            if task_queue.empty() and all(not t.is_alive() for t in threads):
                break
            continue

    stop_event.set()

    while True:
        try:
            rec = timeout_queue.get_nowait()
        except queue.Empty:
            break
        timed_out_records.append(rec)

    producer_thread.join(timeout=2.0)
    for t in threads:
        t.join(timeout=2.0)

    if found is not None:
        line = [
            time.strftime("%Y-%m-%d %H:%M:%S"),
            found.host,
            str(found.port),
            pubkey,
            found.privkey,
            found.found_pubkey or "",
            found.address or "",
            f"{found.start_hex}:{found.end_hex}",
            found.raw_response.replace("\n", "\\n"),
        ]
        if found.status_code is not None:
            line.insert(3, str(found.status_code))
        matches_file.write(",".join(line) + "\n")
        matches_file.flush()
        print(f"[INFO] Saved match for pubkey {pubkey} to matches file", flush=True)

    return found


def main():
    ap = argparse.ArgumentParser(description="Range scanner for keyhunt bsgsd daemon (TCP or HTTP).")
    ap.add_argument("--range", required=True, help="Global hex range from:to (no 0x)")
    ap.add_argument(
        "--chunk-size-hex",
        required=True,
        help="Chunk size in hex (number of keys per chunk, e.g. 100000000 for 2^28)",
    )
    ap.add_argument(
        "--pubkeys-file",
        required=True,
        help="Text file with list of compressed pubkeys (one per line)",
    )
    ap.add_argument(
        "--hosts",
        required=True,
        nargs="+",
        help="List of bsgsd hosts (IP or hostname) to use",
    )
    ap.add_argument("--port", type=int, default=8080, help="bsgsd TCP port (default 8080)")
    ap.add_argument("--timeout-sec", type=float, default=600.0, help="Socket timeout per request (seconds)")
    ap.add_argument("--max-retries", type=int, default=3, help="Max retries per chunk on timeout/error")
    ap.add_argument(
        "--retry-timeouts",
        action="store_true",
        help="If set, chunks that time out are retried up to --max-retries times",
    )
    ap.add_argument(
        "--matches-file",
        default="bsgsd_matches.csv",
        help="CSV file to append matches (timestamp,status?,host,port,pubkey,privkey,found_pubkey,address,range,raw_response)",
    )
    ap.add_argument(
        "--timed-out-file",
        default="timed_out_chunks.txt",
        help="Text file to append chunks that failed after max retries",
    )
    ap.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    ap.add_argument(
        "--http",
        action="store_true",
        help="Use HTTP JSON POST requests instead of raw TCP lines",
    )
    ap.add_argument(
        "--http-path",
        default="/search",
        help="HTTP path to POST to when --http is set (default /search)",
    )
    ap.add_argument(
        "--queue-depth",
        type=int,
        default=1000,
        help="Max queued chunks in memory (producer throttles when full)",
    )
    args = ap.parse_args()

    global_start, global_end = parse_range(args.range)
    chunk_size = hex_to_int(args.chunk_size_hex)
    pubkeys = load_pubkeys(args.pubkeys_file)

    print(f"[INFO] Global range {global_start:x}:{global_end:x}")
    print(f"[INFO] Final chunk size up to {chunk_size:x}", flush=True)
    print(f"[INFO] Hosts: {', '.join(args.hosts)}:{args.port}")
    print(f"[INFO] Loaded {len(pubkeys)} pubkeys from {args.pubkeys_file}")
    if args.verbose:
        print("[INFO] Verbose mode enabled")
    if args.http:
        print(f"[INFO] HTTP mode active, path {args.http_path}")

    timed_out_records: List[TimeoutRecord] = []

    with open(args.matches_file, "a") as mf:
        for idx, pub in enumerate(pubkeys, start=1):
            print(f"\n[INFO] === Target {idx}/{len(pubkeys)}: {pub} ===")
            result = scan_for_pubkey(
                pubkey=pub,
                global_start=global_start,
                global_end=global_end,
                chunk_size=chunk_size,
                hosts=args.hosts,
                port=args.port,
                timeout_sec=args.timeout_sec,
                max_retries=args.max_retries,
                retry_timeouts=args.retry_timeouts,
                matches_file=mf,
                timed_out_records=timed_out_records,
                verbose=args.verbose,
                use_http=args.http,
                http_path=args.http_path,
                queue_max=args.queue_depth,
            )
            if result is None:
                print(f"[INFO] No match found for pubkey {pub} in full range", flush=True)
            else:
                print(f"[INFO] Match found for pubkey {pub}: priv={result.privkey}", flush=True)

    if timed_out_records:
        with open(args.timed_out_file, "a") as tf:
            for rec in timed_out_records:
                tf.write(f"{rec.pubkey} {rec.start_hex}:{rec.end_hex} attempts={rec.attempts}\n")
        print(f"[INFO] {len(timed_out_records)} chunks written to {args.timed_out_file}")
    else:
        print("[INFO] No timed-out chunks.")


if __name__ == "__main__":
    main()
