# port-scanner

TCP port scanner with banner grab, four distinct probe states, latency
stats, aligned table + JSON output, host-list files, and rate limiting
so a wide scan can't SYN-flood a target. Zero dependencies (stdlib only).

**Why it's special:** most toy scanners collapse everything that isn't
"open" into one bucket. This one reports **open / closed / filtered /
error** distinctly, grabs a service banner (connect + read with timeout),
records per-port connect latency, and paces itself twice: a hard
concurrency cap (`StartGate` semaphore) plus an optional start-rate
limiter — both with injectable clock/sleep so the pacing logic is unit
tested against a fake clock with **zero real sleeps**.

## State classification (and one environment note)

| state | meaning |
|---|---|
| `open` | connected; banner grab follows; latency recorded |
| `closed` | connection refused — nothing is listening |
| `filtered` | no answer within the timeout (packets dropped) |
| `error` | other failure (unreachable host, bad address, ...) |

On loopback, some hosts (stealth/firewall configurations — including
this machine) silently drop SYNs to non-listening ports instead of
answering with RST, so a *closed* port would time out and be misreported
as `filtered`. The scanner therefore verifies timeouts **locally**: if
the target is loopback and no local socket holds the port, no service
can exist there → the result is `closed` (`connection refused (no local
listener)`); a held-but-silent port stays `filtered`. Remote targets are
untimed-out semantics: timeout → `filtered`.

## Runnable example

```python
import socket, threading, json
from portscan import PortScanner, format_table, results_to_json

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0)); srv.listen(4)
port = srv.getsockname()[1]

def serve():
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.sendall(b"220 my-ssh-ish service ready\r\n")
        except OSError:
            pass
        conn.close()

threading.Thread(target=serve, daemon=True).start()

probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.bind(("127.0.0.1", 0)); dead = probe.getsockname()[1]; probe.close()

scanner = PortScanner([port, dead], timeout=1.0)
results = scanner.scan("127.0.0.1")
print(format_table(results))
print()
doc = json.loads(results_to_json(results))
print("json states:", [r["state"] for r in doc["results"]])
print("summary:", json.dumps(doc["summary"], sort_keys=True))
srv.close()
```

Output (ports are ephemeral):

```
HOST       PORT   STATE   LATENCY_MS  BANNER
---------  -----  ------  ----------  ----------------------------------------
127.0.0.1  51438  open    29.631      220 my-ssh-ish service ready
127.0.0.1  51439  closed  1014.235    [connection refused (no local listener)]

json states: ['open', 'closed']
summary: {"counts": {"closed": 1, "error": 0, "filtered": 0, "open": 1}, "open_latency_ms": {"avg": 29.631, "max": 29.631, "min": 29.631}, "total": 2}
```

CLI:

```
python portscan.py 127.0.0.1 --ports 22,80,8000-8010 --concurrency 50 --rate 20 --json
python portscan.py --hosts-file hosts.txt --ports 1-1024 --timeout 0.5
```

`--hosts-file`: one host per line, `#` comments allowed. `--rate` caps
probe starts/second; `--concurrency` caps in-flight probes.

## Tests

```
python -m unittest discover -s tests -v
```

24 tests, all against locally bound loopback listeners (nothing leaves
127.0.0.1): open port found; refused localhost port classified `closed`
(the loopback verification path above); filtered via an injected
blackhole connector on a *held* port; `error` state; banner captured
from a scripted listener; banner grab disabled at `--banner-bytes 0`;
mixed-state scan ordering; **concurrency cap** proven with an
instrumented connector (barrier guarantees the cap is *reached*,
a counter proves it is never *exceeded*); StartGate holder cap +
fake-clock pacing (`0, 0.1, 0.2 s` spacing asserted exactly) + unpaced
gate never sleeps; port-spec parsing (ranges, dedupe, invalid input);
hosts-file loading; JSON schema; aligned table columns; state summary;
CLI table/JSON end-to-end.
