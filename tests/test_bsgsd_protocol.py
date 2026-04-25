#!/usr/bin/env python3
"""
BSGSD protocol smoke tests.

Validates both transports (TCP single-line and HTTP POST JSON) plus the
new --bsgs-endo / --honest-counter / --public flags and the
single-flight mutex behavior added in the bug-fix commit.

Tests are skipped (not failed) when:
  - bsgsd binary is not present (i.e. user has not run `make bsgsd`)
  - puzzle-63 bloom/table files are not present (the canonical fixture)

This lets the suite run as a CI smoke test without forcing every
contributor to keep the multi-GB BSGS files locally.

Run with::

    pytest -xvs tests/test_bsgsd_protocol.py

or directly::

    python tests/test_bsgsd_protocol.py
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BSGSD_BIN = REPO_ROOT / "bsgsd"

# Canonical puzzle-63 fixture from BSGSD.md.  If running BSGSD against
# this pubkey + range, the daemon must return this private key (or the
# same modulo a different table size).
PUZZLE63_PUBKEY = (
    "0365ec2994b8cc0a20d40dd69edfe55ca32a54bcbbaa6b0ddcff36049301a54579"
)
PUZZLE63_FROM = "4000000000000000"
PUZZLE63_TO   = "8000000000000000"
PUZZLE63_PRIV = "7cce5efdaccf6808"

# Negative test: a random other pubkey that should NOT be in the range
NEGATIVE_PUBKEY = (
    "0233709eb11e0d4439a729f21c2c443dedb727528229713f0065721ba8fa46f00e"
)


def _free_port() -> int:
    """Grab an ephemeral port for the test daemon."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _bloom_files_present() -> bool:
    """Check whether the puzzle-63 BSGS fixtures exist."""
    # Default keyhunt names from BSGSD.md.  The actual filenames depend
    # on -k and the -n setting; we just check for *any* .blm file in the
    # repo root as a quick "user has prepared fixtures" signal.
    return any(REPO_ROOT.glob("keyhunt_bsgs_*.blm"))


def _bsgsd_available() -> bool:
    return BSGSD_BIN.exists() and os.access(BSGSD_BIN, os.X_OK)


def _start_bsgsd(extra_args: list[str], port: int, ip: str = "127.0.0.1",
                 ready_timeout: float = 60.0) -> subprocess.Popen:
    """Launch bsgsd as a subprocess and wait for the listener to come up."""
    cmd = [str(BSGSD_BIN), "-6", "-t", "2", "-k", "1024",
           "-i", ip, "-p", str(port), "-B", "angrygiant"] + extra_args
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    deadline = time.time() + ready_timeout
    saw_listening = False
    log_buf: list[str] = []
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            log_buf.append(line)
            if "Listening in" in line:
                saw_listening = True
                break
        elif proc.poll() is not None:
            break
        else:
            time.sleep(0.05)
    if not saw_listening:
        # Drain remaining output for diagnostics
        try:
            remainder = proc.stdout.read(8192) or ""
        except Exception:
            remainder = ""
        proc.kill()
        raise RuntimeError(
            "bsgsd did not become ready:\n"
            + "".join(log_buf) + remainder
        )
    return proc


def _stop_bsgsd(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _tcp_request(host: str, port: int, line: str, timeout: float = 60.0) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall((line + "\n").encode("ascii"))
        chunks: list[bytes] = []
        while True:
            try:
                buf = s.recv(4096)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
        return b"".join(chunks).decode("ascii", errors="replace").strip()


def _http_post(host: str, port: int, body: dict,
               timeout: float = 60.0) -> tuple[int, dict[str, str], str]:
    """Minimal HTTP/1.1 client with no third-party deps (since we want this
    test to run in clean envs)."""
    payload = json.dumps(body).encode("utf-8")
    req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + payload
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(req)
        chunks: list[bytes] = []
        while True:
            try:
                buf = s.recv(4096)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
    raw = b"".join(chunks)
    if b"\r\n\r\n" not in raw:
        raise RuntimeError(f"malformed HTTP response: {raw!r}")
    head, _, body_bytes = raw.partition(b"\r\n\r\n")
    head_lines = head.decode("ascii", errors="replace").split("\r\n")
    status = int(head_lines[0].split()[1])
    headers: dict[str, str] = {}
    for h in head_lines[1:]:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    return status, headers, body_bytes.decode("ascii", errors="replace").strip()


@unittest.skipUnless(_bsgsd_available() and _bloom_files_present(),
                     "bsgsd binary or puzzle-63 fixtures not present")
class TestBSGSDProtocol(unittest.TestCase):
    """End-to-end protocol tests against a freshly launched bsgsd."""

    PROC: subprocess.Popen | None = None
    PORT: int = 0

    @classmethod
    def setUpClass(cls):
        cls.PORT = _free_port()
        cls.PROC = _start_bsgsd(extra_args=[], port=cls.PORT)

    @classmethod
    def tearDownClass(cls):
        if cls.PROC is not None:
            _stop_bsgsd(cls.PROC)

    def test_tcp_single_line_found(self):
        """Original AlbertoBSD protocol: <pubkey> <from>:<to>\\n -> hex_priv"""
        reply = _tcp_request(
            "127.0.0.1", self.PORT,
            f"{PUZZLE63_PUBKEY} {PUZZLE63_FROM}:{PUZZLE63_TO}",
        )
        self.assertEqual(reply.lower(), PUZZLE63_PRIV.lower(),
                         f"unexpected reply: {reply!r}")

    def test_tcp_single_line_not_found(self):
        reply = _tcp_request(
            "127.0.0.1", self.PORT,
            f"{NEGATIVE_PUBKEY} {PUZZLE63_FROM}:{PUZZLE63_TO}",
        )
        self.assertEqual(reply, "404 Not Found")

    def test_tcp_single_line_bad_request(self):
        reply = _tcp_request("127.0.0.1", self.PORT, "garbage input")
        self.assertEqual(reply, "400 Bad Request")

    def test_http_post_json_found(self):
        status, headers, body = _http_post("127.0.0.1", self.PORT, {
            "pubkey": PUZZLE63_PUBKEY,
            "from": PUZZLE63_FROM,
            "to": PUZZLE63_TO,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body.lower(), PUZZLE63_PRIV.lower())
        # Default mode (no --honest-counter): only X-Elapsed-Seconds present
        self.assertIn("X-Elapsed-Seconds", headers)
        self.assertNotIn("X-Steps", headers)

    def test_http_post_json_not_found(self):
        status, _hdrs, body = _http_post("127.0.0.1", self.PORT, {
            "pubkey": NEGATIVE_PUBKEY,
            "from": PUZZLE63_FROM,
            "to": PUZZLE63_TO,
        })
        self.assertEqual(status, 404)
        self.assertEqual(body.strip(), "404 Not Found")


@unittest.skipUnless(_bsgsd_available() and _bloom_files_present(),
                     "bsgsd binary or puzzle-63 fixtures not present")
class TestBSGSDHonestCounter(unittest.TestCase):
    """--honest-counter HTTP headers are populated."""

    PROC: subprocess.Popen | None = None
    PORT: int = 0

    @classmethod
    def setUpClass(cls):
        cls.PORT = _free_port()
        cls.PROC = _start_bsgsd(extra_args=["--honest-counter"], port=cls.PORT)

    @classmethod
    def tearDownClass(cls):
        if cls.PROC is not None:
            _stop_bsgsd(cls.PROC)

    def test_x_steps_emitted(self):
        status, headers, _body = _http_post("127.0.0.1", self.PORT, {
            "pubkey": PUZZLE63_PUBKEY,
            "from": PUZZLE63_FROM,
            "to": PUZZLE63_TO,
        })
        self.assertEqual(status, 200)
        self.assertIn("X-Steps", headers)
        self.assertIn("X-BSGS-Endo", headers)
        self.assertEqual(headers["X-BSGS-Endo"], "off")
        for L in (0, 1, 2):
            self.assertIn(f"X-Lane-{L}-Probes", headers)
            self.assertIn(f"X-Lane-{L}-Hits", headers)
            self.assertIn(f"X-Lane-{L}-Recov", headers)
        # Lane 0 must have done some probe work
        self.assertGreater(int(headers["X-Lane-0-Probes"]), 0)
        # Lanes 1/2 should be zero with --bsgs-endo=off
        self.assertEqual(int(headers["X-Lane-1-Probes"]), 0)
        self.assertEqual(int(headers["X-Lane-2-Probes"]), 0)


@unittest.skipUnless(_bsgsd_available() and _bloom_files_present(),
                     "bsgsd binary or puzzle-63 fixtures not present")
class TestBSGSDEndoModes(unittest.TestCase):
    """Each --bsgs-endo mode finds the same key (recovery is correct)."""

    def _run_mode(self, mode: str) -> tuple[str, dict[str, str]]:
        port = _free_port()
        proc = _start_bsgsd(
            extra_args=[f"--bsgs-endo={mode}", "--honest-counter"],
            port=port,
        )
        try:
            status, headers, body = _http_post("127.0.0.1", port, {
                "pubkey": PUZZLE63_PUBKEY,
                "from": PUZZLE63_FROM,
                "to": PUZZLE63_TO,
            })
            self.assertEqual(status, 200, f"mode={mode} body={body!r}")
            self.assertEqual(body.lower(), PUZZLE63_PRIV.lower(),
                             f"mode={mode} returned wrong key")
            return body, headers
        finally:
            _stop_bsgsd(proc)

    def test_endo_off(self):
        body, hdrs = self._run_mode("off")
        self.assertEqual(hdrs["X-BSGS-Endo"], "off")

    def test_endo_keyhunt(self):
        body, hdrs = self._run_mode("keyhunt")
        self.assertEqual(hdrs["X-BSGS-Endo"], "keyhunt")
        # With endo enabled, lane 0 must still recover the key (since
        # the puzzle-63 key is in [from,to] directly).  Lanes 1/2 will
        # have probed but not recovered.
        self.assertGreater(int(hdrs["X-Lane-0-Probes"]), 0)
        self.assertGreater(int(hdrs["X-Lane-1-Probes"]), 0)
        self.assertGreater(int(hdrs["X-Lane-2-Probes"]), 0)

    def test_endo_glv12(self):
        body, hdrs = self._run_mode("glv12")
        self.assertEqual(hdrs["X-BSGS-Endo"], "glv12")


@unittest.skipUnless(_bsgsd_available() and _bloom_files_present(),
                     "bsgsd binary or puzzle-63 fixtures not present")
class TestBSGSDSingleFlightMutex(unittest.TestCase):
    """Concurrent requests must serialize via single_search_mutex."""

    PROC: subprocess.Popen | None = None
    PORT: int = 0

    @classmethod
    def setUpClass(cls):
        cls.PORT = _free_port()
        cls.PROC = _start_bsgsd(extra_args=[], port=cls.PORT)

    @classmethod
    def tearDownClass(cls):
        if cls.PROC is not None:
            _stop_bsgsd(cls.PROC)

    def test_two_concurrent_clients_both_succeed(self):
        """Both connections complete and both return correct results.
        The second one waits server-side; we only check it does not
        crash, race, or return garbage."""
        results: list[str] = [None, None]  # type: ignore

        def worker(idx: int):
            results[idx] = _tcp_request(
                "127.0.0.1", self.PORT,
                f"{PUZZLE63_PUBKEY} {PUZZLE63_FROM}:{PUZZLE63_TO}",
            )

        t1 = threading.Thread(target=worker, args=(0,))
        t2 = threading.Thread(target=worker, args=(1,))
        t1.start()
        # Slight stagger so we know t2 hits the mutex
        time.sleep(0.1)
        t2.start()
        t1.join(timeout=180)
        t2.join(timeout=180)
        self.assertIsNotNone(results[0])
        self.assertIsNotNone(results[1])
        self.assertEqual(results[0].lower(), PUZZLE63_PRIV.lower())
        self.assertEqual(results[1].lower(), PUZZLE63_PRIV.lower())


@unittest.skipUnless(_bsgsd_available(),
                     "bsgsd binary not present")
class TestBSGSDBindHostname(unittest.TestCase):
    """Hostname binding via getaddrinfo (regression for bug #2 in B)."""

    def test_localhost_hostname_resolves(self):
        port = _free_port()
        proc = _start_bsgsd(extra_args=[], port=port, ip="localhost",
                            ready_timeout=20)
        try:
            # If bsgsd actually bound to 127.0.0.1 (resolved hostname),
            # we should be able to connect.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(("127.0.0.1", port))
        finally:
            _stop_bsgsd(proc)

    def test_public_alias(self):
        """--public must bind 0.0.0.0 even if -i wasn't given."""
        port = _free_port()
        proc = _start_bsgsd(extra_args=["--public"], port=port,
                            ip="", ready_timeout=20)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(("127.0.0.1", port))
        finally:
            _stop_bsgsd(proc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
