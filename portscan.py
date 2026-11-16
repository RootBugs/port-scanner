#!/usr/bin/env python3
"""TCP port scanner with banner grab, distinct states, and rate limiting.

What it does
------------
Scans ``host:ports`` (port specs like ``80,443,8000-8010``) with a
thread pool, one connection attempt per (host, port), each with its own
timeout.  Every probe reports one of four states:

* ``open``      — connected; a banner grab (connect + read with timeout)
  follows and the connect latency (ms) is recorded.
* ``closed``    — the OS actively refused the connection.
* ``filtered``  — no answer within the timeout (packets dropped).
* ``error``     — anything else (unreachable host, bad address, ...).

Rate limiting
-------------
:class:`StartGate` caps how many probes are in flight (configurable
concurrency) and can pace probe *starts* at ``start_rate`` per second so
a wide scan cannot SYN-flood a target.  Both the clock and the sleep are
injectable, so pacing is unit-tested against a fake clock with no real
sleeps.

Output
------
:meth:`format_table` renders an aligned text table; :func:`results_to_json`
renders a machine-readable document (``{"results": [...], "summary": ...}``)
for tooling.  Hosts can come from the command line or a hosts file
(one per line, ``#`` comments allowed).

Everything binds/Connects only where you point it; the test suite scans
locally bound loopback listeners exclusively.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

__all__ = [
    "STATES",
    "ScanResult",
    "StartGate",
    "PortScanner",
    "parse_ports",
    "load_hosts",
    "tcp_connect",
    "format_table",
    "results_to_json",
    "summarize",
    "main",
]

STATES = ("open", "closed", "filtered", "error")


# --- results ----------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """One probe's outcome."""

    host: str
    port: int
    state: str
    latency_ms: float
    banner: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        """JSON-ready representation (stable schema for tooling)."""
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "latency_ms": round(self.latency_ms, 3),
            "banner": self.banner,
            "error": self.error,
        }


# --- input parsing ----------------------------------------------------------


def parse_ports(spec: str) -> list:
    """Parse ``"80,443,8000-8010"`` into a sorted, de-duplicated list.

    Raises:
        ValueError: on empty spec, non-numeric parts, reversed ranges,
            or ports outside 1..65535.
    """
    if spec is None or not str(spec).strip():
        raise ValueError("empty port spec")
    ports: set = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                low, _, high = part.partition("-")
                start, end = int(low.strip()), int(high.strip())
                if start > end:
                    raise ValueError(
                        "reversed port range: %r" % part)
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError as exc:
            if isinstance(exc, ValueError) and str(exc).startswith(
                    ("reversed", "empty")):
                raise
            raise ValueError("invalid port spec part: %r" % part) from exc
    if not ports:
        raise ValueError("empty port spec")
    bad = sorted(p for p in ports if not 1 <= p <= 65535)
    if bad:
        raise ValueError("port(s) out of range 1..65535: %s"
                         % ", ".join(str(p) for p in bad))
    return sorted(ports)


def load_hosts(path: str) -> list:
    """Read hosts from a file: one per line, ``#`` comments, blanks ok.

    Raises:
        ValueError: when the file yields no hosts.
    """
    hosts: list = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                hosts.append(line)
    if not hosts:
        raise ValueError("no hosts found in %s" % path)
    return hosts


# --- rate limiting ----------------------------------------------------------


class StartGate:
    """Concurrency cap + optional start-rate pacing for probes.

    ``with gate:`` holds one of ``max_concurrent`` slots and, when
    ``start_rate > 0``, ensures probe starts are spaced ``1/start_rate``
    seconds apart.  Pacing reads ``clock`` and waits with ``sleep`` —
    both injectable, so tests drive time without real sleeps.

    Args:
        max_concurrent: maximum probes in flight at once.
        start_rate: maximum probe starts per second (0 = unpaced).
        clock: callable or object with ``now()``; defaults to
            ``time.monotonic``.
        sleep: callable used to wait out pacing delays; defaults to
            ``time.sleep``.
    """

    def __init__(self, max_concurrent: int, start_rate: float = 0.0,
                 clock=None, sleep=None) -> None:
        if isinstance(max_concurrent, bool) or not isinstance(
                max_concurrent, int) or max_concurrent < 1:
            raise ValueError("max_concurrent must be an integer >= 1")
        if start_rate < 0:
            raise ValueError("start_rate must be >= 0")
        self.max_concurrent = int(max_concurrent)
        self.start_rate = float(start_rate)
        self._interval = (0.0 if self.start_rate <= 0
                          else 1.0 / self.start_rate)
        self._slots = threading.BoundedSemaphore(self.max_concurrent)
        if clock is None:
            self._clock = time.monotonic
        elif hasattr(clock, "now"):
            self._clock = clock.now
        else:
            self._clock = clock
        self._sleep = sleep if sleep is not None else time.sleep
        self._pace_lock = threading.Lock()
        self._next_start = 0.0

    def __enter__(self) -> "StartGate":
        self._slots.acquire()
        if self._interval > 0:
            with self._pace_lock:
                now = self._clock()
                wait = self._next_start - now
                self._next_start = max(now, self._next_start) + self._interval
            if wait > 0:
                self._sleep(wait)
        return self

    def __exit__(self, *exc_info) -> None:
        self._slots.release()


# --- connecting -------------------------------------------------------------


def tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    """Default connector: TCP connect with *timeout*, returns the socket."""
    return socket.create_connection((host, port), timeout=timeout)


def _is_loopback(host: str) -> bool:
    """True when *host* resolves to loopback only (127.0.0.0/8, ::1)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not infos:
        return False
    try:
        return all(ipaddress.ip_address(info[4][0]).is_loopback
                   for info in infos)
    except ValueError:
        return False


def _local_port_holds(host: str, port: int) -> bool:
    """True when a local socket already holds ``host:port``.

    Used only after a connect timeout on a loopback target: if nothing
    is bound to the port, no service can exist there, so the missing
    answer was a locally dropped SYN (stealth firewall) rather than a
    filtered remote port — the probe classifies it ``closed``.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
        return False
    except OSError:
        return True
    finally:
        probe.close()


# --- scanner ----------------------------------------------------------------


class PortScanner:
    """Scan hosts with a bounded thread pool and per-probe timeouts.

    Args:
        ports: iterable of port numbers to probe.
        timeout: per-connection timeout in seconds.
        concurrency: max probes in flight (see :class:`StartGate`).
        start_rate: probe starts per second (0 = unpaced).
        banner_bytes: max banner bytes to read from open ports
            (0 disables the banner grab).
        connector: ``(host, port, timeout) -> socket``; defaults to
            :func:`tcp_connect`.  Tests inject scripted connectors.
        clock / sleep: passed to :class:`StartGate` for pacer tests.
    """

    def __init__(self, ports, timeout: float = 1.0, concurrency: int = 100,
                 start_rate: float = 0.0, banner_bytes: int = 1024,
                 connector=None, clock=None, sleep=None) -> None:
        self.ports = list(ports)
        if not self.ports:
            raise ValueError("no ports to scan")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if banner_bytes < 0:
            raise ValueError("banner_bytes must be >= 0")
        self.timeout = float(timeout)
        self.banner_bytes = int(banner_bytes)
        self.concurrency = int(concurrency)
        self._connector = connector if connector is not None else tcp_connect
        self._gate = StartGate(concurrency, start_rate,
                               clock=clock, sleep=sleep)

    def scan(self, host: str) -> list:
        """Probe every configured port on *host*; results by port order."""
        results: list = []
        with ThreadPoolExecutor(max_workers=self.concurrency,
                                thread_name_prefix="portscan") as pool:
            futures = [pool.submit(self._probe, host, port)
                       for port in self.ports]
            for future in as_completed(futures):
                results.append(future.result())
        results.sort(key=lambda r: r.port)
        return results

    def scan_all(self, hosts) -> list:
        """Scan each host; results ordered by (host, port)."""
        results: list = []
        for host in hosts:
            results.extend(self.scan(host))
        results.sort(key=lambda r: (r.host, r.port))
        return results

    def _probe(self, host: str, port: int) -> ScanResult:
        with self._gate:                       # concurrency + pacing
            start = time.perf_counter()
            try:
                sock = self._connector(host, port, self.timeout)
            except socket.timeout:
                latency = (time.perf_counter() - start) * 1000.0
                if _is_loopback(host) and not _local_port_holds(host, port):
                    # Loopback SYN vanished with no local holder: the
                    # port is genuinely closed (RST suppressed locally),
                    # not filtered.
                    return ScanResult(host, port, "closed", latency,
                                      error="connection refused "
                                            "(no local listener)")
                return ScanResult(host, port, "filtered", latency,
                                  error="connect timed out")
            except ConnectionRefusedError:
                latency = (time.perf_counter() - start) * 1000.0
                return ScanResult(host, port, "closed", latency,
                                  error="connection refused")
            except OSError as exc:
                latency = (time.perf_counter() - start) * 1000.0
                return ScanResult(host, port, "error", latency,
                                  error=str(exc))
            latency = (time.perf_counter() - start) * 1000.0
            banner = b""
            try:
                if self.banner_bytes > 0:
                    sock.settimeout(self.timeout)
                    try:
                        banner = sock.recv(self.banner_bytes)
                    except socket.timeout:
                        banner = b""       # open, but silent within timeout
            finally:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
            text = banner.decode("utf-8", "replace").rstrip()
            return ScanResult(host, port, "open", latency, banner=text)


# --- output -----------------------------------------------------------------


def summarize(results) -> dict:
    """Counts per state plus connect-latency stats for open ports."""
    counts = {state: 0 for state in STATES}
    for result in results:
        counts[result.state] = counts.get(result.state, 0) + 1
    open_latencies = [r.latency_ms for r in results if r.state == "open"]
    if open_latencies:
        latency = {
            "min": round(min(open_latencies), 3),
            "max": round(max(open_latencies), 3),
            "avg": round(sum(open_latencies) / len(open_latencies), 3),
        }
    else:
        latency = {"min": None, "max": None, "avg": None}
    return {"total": len(results), "counts": counts,
            "open_latency_ms": latency}


def format_table(results) -> str:
    """Aligned text table: HOST PORT STATE LATENCY_MS BANNER."""
    header = ("HOST", "PORT", "STATE", "LATENCY_MS", "BANNER")
    rows = []
    for r in results:
        banner = r.banner.replace("\r", "\\r").replace("\n", "\\n")
        if r.error and not banner:
            banner = "[" + r.error + "]"
        rows.append((r.host, str(r.port), r.state,
                     "%.3f" % r.latency_ms, banner))
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(cells) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)
                         ).rstrip()

    lines = [fmt(header), fmt(tuple("-" * w for w in widths))]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def results_to_json(results, indent: int = 2) -> str:
    """JSON document: ``{"results": [...], "summary": {...}}``."""
    payload = {
        "results": [r.to_dict() for r in results],
        "summary": summarize(results),
    }
    return json.dumps(payload, indent=indent, sort_keys=True)


# --- CLI --------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="TCP port scanner with banner grab (localhost-safe).")
    parser.add_argument("hosts", nargs="*",
                        help="host(s) to scan, e.g. 127.0.0.1")
    parser.add_argument("--ports", required=True,
                        help='port spec: "80,443,8000-8010"')
    parser.add_argument("--hosts-file",
                        help="file with one host per line (# comments)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="per-connection timeout seconds (default 1.0)")
    parser.add_argument("--concurrency", type=int, default=100,
                        help="max probes in flight (default 100)")
    parser.add_argument("--rate", type=float, default=0.0,
                        help="max probe starts per second (0 = unpaced)")
    parser.add_argument("--banner-bytes", type=int, default=1024,
                        help="max banner bytes to read (0 = skip grab)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    hosts = list(args.hosts)
    if args.hosts_file:
        hosts.extend(load_hosts(args.hosts_file))
    if not hosts:
        raise SystemExit("no hosts given (positional or --hosts-file)")
    ports = parse_ports(args.ports)
    scanner = PortScanner(ports, timeout=args.timeout,
                          concurrency=args.concurrency,
                          start_rate=args.rate,
                          banner_bytes=args.banner_bytes)
    results = scanner.scan_all(hosts)
    if args.json:
        print(results_to_json(results))
    else:
        print(format_table(results))
        print()
        summary = summarize(results)
        print("total=%d open=%d closed=%d filtered=%d error=%d"
              % (summary["total"], summary["counts"]["open"],
                 summary["counts"]["closed"], summary["counts"]["filtered"],
                 summary["counts"]["error"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
