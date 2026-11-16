"""Tests for the TCP port scanner.

Every network test targets **locally bound loopback listeners** on
ephemeral ports — nothing leaves 127.0.0.1.  Concurrency is asserted via
an instrumented connector (a barrier guarantees the cap is actually
reached, a counter proves it is never exceeded).  StartGate pacing is
driven by an injected fake clock — zero real sleeps in the suite.
"""

import io
import json
import os
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

from portscan import (
    PortScanner,
    StartGate,
    format_table,
    load_hosts,
    main,
    parse_ports,
    results_to_json,
    summarize,
    tcp_connect,
)


class ScriptedListener:
    """Loopback listener on an ephemeral port; optionally sends a banner."""

    def __init__(self, banner: bytes = b""):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self.banner = banner
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                self._sock.settimeout(0.2)   # teardown poll, not logic
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.accepted += 1
                if self.banner:
                    try:
                        conn.sendall(self.banner)
                    except OSError:
                        pass      # peer may have closed already
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=5.0)
        try:
            self._sock.close()
        except OSError:
            pass


def closed_port() -> int:
    """A loopback port that is definitely not listening."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class ScanStateTests(unittest.TestCase):

    def setUp(self):
        self.listeners = []

    def tearDown(self):
        for listener in self.listeners:
            listener.close()

    def listener(self, banner=b""):
        listener = ScriptedListener(banner)
        self.listeners.append(listener)
        return listener

    def test_open_port_found(self):
        listener = self.listener()
        scanner = PortScanner([listener.port], timeout=2.0)
        results = scanner.scan("127.0.0.1")
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.state, "open")
        self.assertEqual(result.host, "127.0.0.1")
        self.assertEqual(result.port, listener.port)
        self.assertGreaterEqual(result.latency_ms, 0.0)
        self.assertEqual(listener.accepted, 1)

    def test_closed_port_reported_closed(self):
        port = closed_port()
        scanner = PortScanner([port], timeout=2.0)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "closed")
        self.assertIn("refused", result.error)
        self.assertEqual(result.banner, "")

    def test_filtered_state_when_connector_times_out(self):
        # a port that IS held locally but never answers: the loopback
        # verification must still classify it filtered, not closed
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        self.addCleanup(holder.close)

        def blackhole(host, target, timeout):
            raise socket.timeout("connect timed out after %ss" % timeout)

        scanner = PortScanner([port], timeout=0.05, connector=blackhole)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "filtered")
        self.assertIn("timed out", result.error)

    def test_error_state_on_unreachable_style_failure(self):
        def unreachable(host, target, timeout):
            raise OSError("getaddrinfo failed: name or service not known")

        scanner = PortScanner([80], connector=unreachable)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "error")
        self.assertIn("getaddrinfo", result.error)

    def test_banner_captured_from_scripted_listener(self):
        listener = self.listener(banner=b"220 test-banner ready\r\n")
        scanner = PortScanner([listener.port], timeout=2.0)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "220 test-banner ready")

    def test_open_port_without_banner_reports_empty_banner(self):
        listener = self.listener()   # accepts and closes: recv sees EOF
        scanner = PortScanner([listener.port], timeout=2.0)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "")

    def test_banner_bytes_zero_disables_grab(self):
        listener = self.listener(banner=b"should-not-be-read")
        scanner = PortScanner([listener.port], timeout=2.0, banner_bytes=0)
        result = scanner.scan("127.0.0.1")[0]
        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "")

    def test_mixed_states_in_one_scan(self):
        open_listener = self.listener(banner=b"220 hi\r\n")
        refused = closed_port()
        scanner = PortScanner([open_listener.port, refused], timeout=2.0)
        results = scanner.scan("127.0.0.1")
        by_port = {r.port: r for r in results}
        self.assertEqual(by_port[open_listener.port].state, "open")
        self.assertEqual(by_port[refused].state, "closed")
        # sorted by port, one result per port
        self.assertEqual([r.port for r in results],
                         sorted([open_listener.port, refused]))


class ConcurrencyTests(unittest.TestCase):

    def test_concurrency_cap_respected(self):
        listeners = [ScriptedListener() for _ in range(6)]
        try:
            cap = 2
            lock = threading.Lock()
            tracker = {"inflight": 0, "max": 0}
            # barrier(2) forces two probes in flight simultaneously, so
            # the "cap is reached" side of the assertion is guaranteed
            barrier = threading.Barrier(2, timeout=15.0)

            def instrumented(host, port, timeout):
                with lock:
                    tracker["inflight"] += 1
                    tracker["max"] = max(tracker["max"],
                                         tracker["inflight"])
                try:
                    barrier.wait()
                    return tcp_connect(host, port, timeout)
                finally:
                    with lock:
                        tracker["inflight"] -= 1

            ports = [listener.port for listener in listeners]
            scanner = PortScanner(ports, timeout=2.0, concurrency=cap,
                                  banner_bytes=0,
                                  connector=instrumented)
            results = scanner.scan("127.0.0.1")

            self.assertEqual(len(results), 6)
            self.assertTrue(all(r.state == "open" for r in results))
            self.assertLessEqual(tracker["max"], cap,
                                 "cap exceeded: %d in flight" % tracker["max"])
            self.assertGreaterEqual(tracker["max"], 2,
                                    "cap never reached — test is vacuous")
        finally:
            for listener in listeners:
                listener.close()

    def test_startgate_limits_concurrent_holders(self):
        gate = StartGate(max_concurrent=2)
        lock = threading.Lock()
        tracker = {"inside": 0, "max": 0}
        barrier = threading.Barrier(2, timeout=15.0)

        def worker():
            with gate:
                with lock:
                    tracker["inside"] += 1
                    tracker["max"] = max(tracker["max"], tracker["inside"])
                try:
                    barrier.wait()
                finally:
                    with lock:
                        tracker["inside"] -= 1

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20.0)
        self.assertFalse(any(t.is_alive() for t in threads),
                         "gate deadlocked")
        self.assertEqual(tracker["max"], 2)

    def test_startgate_rate_pacing_uses_injected_clock(self):
        class FakeTime:
            def __init__(self):
                self.t = 0.0

            def now(self):
                return self.t

            def sleep(self, seconds):
                self.t += seconds

        fake = FakeTime()
        gate = StartGate(max_concurrent=4, start_rate=10.0,
                         clock=fake, sleep=fake.sleep)
        with gate:
            pass
        first = fake.t
        with gate:
            pass
        with gate:
            pass
        # starts spaced 1/10 s apart; first start is immediate
        self.assertEqual(first, 0.0)
        self.assertAlmostEqual(fake.t, 0.2, places=9)

    def test_startgate_unpaced_never_sleeps(self):
        sleeps = []
        gate = StartGate(max_concurrent=8, start_rate=0.0,
                         clock=lambda: 0.0, sleep=sleeps.append)
        for _ in range(5):
            with gate:
                pass
        self.assertEqual(sleeps, [])


class PortSpecTests(unittest.TestCase):

    def test_parse_ports_ranges_lists_and_dedupe(self):
        self.assertEqual(parse_ports("80,443,8000-8002"),
                         [80, 443, 8000, 8001, 8002])
        self.assertEqual(parse_ports("443,80,443"), [80, 443])
        self.assertEqual(parse_ports(" 22 "), [22])

    def test_parse_ports_rejects_invalid_input(self):
        for bad in ("", "   ", "abc", "0", "65536", "10-5", "80-", "1,,2-"):
            with self.subTest(spec=bad):
                with self.assertRaises(ValueError):
                    parse_ports(bad)

    def test_load_hosts_file_with_comments_and_blanks(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8")
        try:
            handle.write("# lab hosts\n127.0.0.1\n\n  localhost  # loopback\n")
            handle.close()
            hosts = load_hosts(handle.name)
            self.assertEqual(hosts, ["127.0.0.1", "localhost"])
        finally:
            os.unlink(handle.name)

    def test_load_hosts_rejects_empty_file(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8")
        try:
            handle.write("# nothing here\n\n")
            handle.close()
            with self.assertRaises(ValueError):
                load_hosts(handle.name)
        finally:
            os.unlink(handle.name)


class OutputTests(unittest.TestCase):

    def test_json_output_schema(self):
        # build real results via a live scan to keep types honest
        listener = ScriptedListener(banner=b"220 json\r\n")
        try:
            results = PortScanner([listener.port], timeout=2.0).scan(
                "127.0.0.1")
            document = json.loads(results_to_json(results))
        finally:
            listener.close()

        self.assertEqual(set(document), {"results", "summary"})
        self.assertEqual(len(document["results"]), 1)
        entry = document["results"][0]
        self.assertEqual(set(entry),
                         {"host", "port", "state", "latency_ms",
                          "banner", "error"})
        self.assertEqual(entry["state"], "open")
        self.assertEqual(entry["banner"], "220 json")
        self.assertIsInstance(entry["latency_ms"], float)
        self.assertIsInstance(entry["port"], int)

        summary = document["summary"]
        self.assertEqual(set(summary),
                         {"total", "counts", "open_latency_ms"})
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["counts"]["open"], 1)
        self.assertIsInstance(summary["open_latency_ms"]["avg"], float)

    def test_table_output_columns_are_aligned(self):
        listener = ScriptedListener(banner=b"220 t\r\n")
        try:
            results = PortScanner([listener.port, closed_port()],
                                  timeout=2.0).scan("127.0.0.1")
        finally:
            listener.close()
        table = format_table(results)
        lines = table.splitlines()
        self.assertGreaterEqual(len(lines), 4)   # header, rule, 2 rows
        header = lines[0]
        for column in ("HOST", "PORT", "STATE", "LATENCY_MS", "BANNER"):
            self.assertIn(column, header)
        state_col = header.index("STATE")
        data_lines = [line for line in lines[1:]
                      if not set(line) <= {"-", " "}]
        self.assertEqual(len(data_lines), 2)
        for line in data_lines:
            # the state token starts at exactly the STATE column
            self.assertIn(line[state_col:].split()[0],
                          ("open", "closed", "filtered", "error"))
        self.assertIn("closed", table)

    def test_summarize_counts_states(self):
        listener = ScriptedListener()
        try:
            results = PortScanner([listener.port, closed_port()],
                                  timeout=2.0).scan("127.0.0.1")
        finally:
            listener.close()
        summary = summarize(results)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"]["open"], 1)
        self.assertEqual(summary["counts"]["closed"], 1)
        self.assertEqual(summary["counts"]["filtered"], 0)
        self.assertIsNotNone(summary["open_latency_ms"]["min"])
        self.assertLessEqual(summary["open_latency_ms"]["min"],
                             summary["open_latency_ms"]["max"])


class ScannerValidationTests(unittest.TestCase):

    def test_empty_ports_rejected(self):
        with self.assertRaises(ValueError):
            PortScanner([])

    def test_nonpositive_timeout_rejected(self):
        with self.assertRaises(ValueError):
            PortScanner([80], timeout=0)


class CliTests(unittest.TestCase):

    def test_cli_json_end_to_end_on_loopback(self):
        listener = ScriptedListener(banner=b"220 cli\r\n")
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["127.0.0.1",
                             "--ports", str(listener.port),
                             "--timeout", "2",
                             "--json"])
        finally:
            listener.close()
        self.assertEqual(code, 0)
        document = json.loads(buffer.getvalue())
        self.assertEqual(document["results"][0]["state"], "open")
        self.assertEqual(document["results"][0]["banner"], "220 cli")

    def test_cli_table_end_to_end_on_loopback(self):
        listener = ScriptedListener()
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["127.0.0.1",
                             "--ports", str(listener.port),
                             "--timeout", "2"])
        finally:
            listener.close()
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("HOST", output)
        self.assertIn("open", output)
        self.assertIn("total=1 open=1", output)

    def test_cli_requires_ports(self):
        with self.assertRaises(SystemExit):
            main(["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
