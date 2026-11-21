"""Generate and record bounded benign transactions on the G26 internal lab."""

import argparse
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import json
from pathlib import Path
from random import Random
from signal import SIGINT
import socket
import subprocess
import sys
from threading import Event, Thread
from time import monotonic, sleep

from ml.lab_registry import identifier, read_object, write_new_object
from ml.lab_zeek import run_zeek


CLIENT = "10.75.26.20"
SENSOR = "10.75.26.10"
LAB_INTERFACE = "lab0"
CONTROL_PORT, HTTP_PORT, UDP_PORT = 8090, 8001, 8053
TIMEOUT = 8


def utc_now():
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def bounded_integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"expected an integer in [{low}, {high}]")
    return value


@dataclass(frozen=True)
class Transaction:
    id: str
    method: str
    payload: bytes
    delay_ms: int
    gap_ms: int
    last: bool

    @property
    def request(self):
        return b"" if self.method == "get" else self.payload

    @property
    def response(self):
        return self.payload if self.method == "get" else sha256(self.payload).digest()


def plan(document):
    if document.keys() != {"version", "sessions"} or type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("expected version 1 and sessions")
    sessions = document["sessions"]
    if not isinstance(sessions, list) or not 1 <= len(sessions) <= 8:
        raise ValueError("plan must contain one to eight sessions")
    result, session_ids, seeds = {}, set(), set()
    for session in sessions:
        if not isinstance(session, dict) or session.keys() != {"capture_id", "session_id", "seed", "connections"}:
            raise ValueError("unexpected session fields")
        capture_id, session_id = identifier(session["capture_id"]), identifier(session["session_id"])
        seed = bounded_integer(session["seed"], 0, 2**32 - 1)
        if capture_id in result or session_id in session_ids or seed in seeds:
            raise ValueError("capture IDs, session IDs, and seeds must be unique")
        session_ids.add(session_id)
        seeds.add(seed)
        connections = session["connections"]
        if not isinstance(connections, list) or not 1 <= len(connections) <= 16:
            raise ValueError("session must contain one to sixteen connections")
        random = Random(seed)
        groups = []
        for index, step in enumerate(connections, 1):
            if not isinstance(step, dict) or step.keys() != {
                "method", "requests", "min_bytes", "max_bytes", "delay_ms", "gap_ms",
            }:
                raise ValueError("unexpected connection fields")
            method = step["method"]
            if method not in ("get", "post", "udp"):
                raise ValueError("unsupported benign operation")
            requests = bounded_integer(step["requests"], 1, 4)
            limit = 512 if method == "udp" else 16_384
            first = bounded_integer(step["min_bytes"], 1, limit)
            last = bounded_integer(step["max_bytes"], first, limit)
            delay = bounded_integer(step["delay_ms"], 0, 250)
            gap = bounded_integer(step["gap_ms"], 20, 500)
            groups.append(tuple(
                Transaction(f"{index}-{request}", method, random.randbytes(random.randint(first, last)),
                            delay, gap, request == requests)
                for request in range(1, requests + 1)
            ))
        result[capture_id] = (session, groups)
    return result


def verify_isolation(role, route_checks):
    """Check the guest namespace locally before opening a lab socket."""
    local = SENSOR if role == "sensor" else CLIENT
    addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show"]))
    if {row["ifname"] for row in addresses} != {"lo", LAB_INTERFACE}:
        raise ValueError("expected only loopback and the dedicated lab interface")
    lab = next(row for row in addresses if row["ifname"] == LAB_INTERFACE)
    if [(row["local"], row["prefixlen"]) for row in lab["addr_info"]] != [(local, 24)]:
        raise ValueError("unexpected address on lab interface")
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "main"]))
    if len(routes) != 1 or routes[0].get("dst") != "10.75.26.0/24" or routes[0].get("dev") != LAB_INTERFACE:
        raise ValueError("guest has a route outside the dedicated lab subnet")
    if json.loads(subprocess.check_output(["ip", "-j", "-6", "route", "show", "table", "main"])):
        raise ValueError("unexpected IPv6 route")
    for setting in ("ipv4/ip_forward", "ipv6/conf/all/forwarding"):
        if Path(f"/proc/sys/net/{setting}").read_text().strip() != "0":
            raise ValueError("guest IP forwarding is enabled")
    if set(route_checks) != {"host", "lan_gateway", "internet_ipv4", "internet_ipv6"}:
        raise ValueError("the four isolation route probes are required")
    no_route = []
    for name, target in route_checks.items():
        address = ip_address(target)
        result = subprocess.run(["ip", f"-{address.version}", "route", "get", str(address)],
                                capture_output=True, text=True, check=False)
        if result.returncode != 2 or "Network is unreachable" not in result.stderr:
            raise ValueError(f"route isolation check failed: {name}")
        no_route.append(name)
    return {"role": role, "local": local, "checked_utc": utc_now(), "no_route": sorted(no_route),
            "lab_route": "10.75.26.0/24", "forwarding": False}


def settings_for_capture():
    subprocess.run(["ethtool", "-K", LAB_INTERFACE, "tx", "off", "tso", "off", "gso", "off", "gro", "off"],
                   check=True)


def event(transaction, endpoints, start):
    return {"id": transaction.id, "method": transaction.method, "endpoints": endpoints,
            "start": start, "end": utc_now(),
            "request_bytes": len(transaction.request), "response_bytes": len(transaction.response),
            "request_sha256": sha256(transaction.request).hexdigest(),
            "response_sha256": sha256(transaction.response).hexdigest()}


def socket_endpoints(source_port, target_port):
    return [CLIENT, source_port, SENSOR, target_port]


def client_group(group):
    events = []
    udp = group[0].method == "udp"
    endpoint = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if udp
                else HTTPConnection(SENSOR, HTTP_PORT, timeout=TIMEOUT, source_address=(CLIENT, 0)))
    with closing(endpoint) as connection:
        if udp:
            connection.settimeout(TIMEOUT)
            connection.bind((CLIENT, 0))
            connection.connect((SENSOR, UDP_PORT))
            endpoints = socket_endpoints(connection.getsockname()[1], UDP_PORT)
        else:
            connection.connect()
            endpoints = socket_endpoints(connection.sock.getsockname()[1], HTTP_PORT)
        for transaction in group:
            started = utc_now()
            if udp:
                connection.send(transaction.id.encode("ascii") + b"\0" + transaction.request)
                body = connection.recv(64)
            else:
                connection.request(transaction.method.upper(), "/lab/" + transaction.id, transaction.request,
                                   {"Connection": "close" if transaction.last else "keep-alive"})
                reply = connection.getresponse()
                body = reply.read(16_385)
                if reply.status != 200:
                    raise ValueError("unexpected lab HTTP status")
            if body != transaction.response:
                raise ValueError("lab service response differs from the planned payload")
            events.append(event(transaction, endpoints, started))
            sleep(transaction.gap_ms / 1000)
    return events


def control(action, capture_id, isolation=None):
    body = json.dumps({"capture_id": capture_id, "isolation": isolation})
    with closing(HTTPConnection(SENSOR, CONTROL_PORT, timeout=25, source_address=(CLIENT, 0))) as connection:
        connection.request("POST", "/" + action, body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read(4096)
        if response.status != 200:
            raise ValueError(f"local capture coordinator rejected {action}")


def run_client(root, sessions, route_checks):
    isolation = verify_isolation("client", route_checks)
    settings_for_capture()
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    for capture_id, (_, groups) in sessions.items():
        control("start", capture_id, isolation)
        events = [entry for group in groups for entry in client_group(group)]
        write_new_object(root / f"evidence/{capture_id}-client.json", {
            "isolation": isolation, "capture_id": capture_id, "events": events,
        })
        control("finish", capture_id)


class Recorder:
    """Own one bounded tcpdump process at a time."""

    def __init__(self, root, capture_id):
        self.path = root / f"raw/{capture_id}.pcap"
        self.stats = root / f"evidence/{capture_id}-tcpdump.txt"
        if self.path.exists() or self.stats.exists():
            raise FileExistsError("recording already exists")
        self.start = utc_now()
        with self.stats.open("xb") as diagnostics:
            self.process = subprocess.Popen(
                ["tcpdump", "-i", LAB_INTERFACE, "-s", "0", "--immediate-mode", "-U", "-n", "-Z", "root", "-c", "10000",
                 "-w", str(self.path), "host", CLIENT, "and",
                 "(", "tcp", "port", str(HTTP_PORT), "or", "udp", "port", str(UDP_PORT), ")"],
                stdout=diagnostics, stderr=diagnostics,
            )
        expires = monotonic() + 5
        while monotonic() < expires and self.process.poll() is None:
            if "listening on" in self.stats.read_text(errors="replace"):
                return
            sleep(0.05)
        self.stop()
        raise ValueError("lab recorder did not become ready")

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(SIGINT)
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        if code:
            raise ValueError("lab recorder stopped with an error")
        return utc_now()


class SensorRun:
    def __init__(self, root, sessions, route_checks, zeek):
        self.root, self.zeek = root, zeek
        self.isolation = verify_isolation("sensor", route_checks)
        settings_for_capture()
        self.remaining = dict(sessions)
        self.done = Event()
        self.failure = None
        self.recorder = None

    def start(self, capture_id, client_proof):
        if self.recorder is not None or capture_id != next(iter(self.remaining), None):
            raise ValueError("unexpected capture request")
        if client_proof.get("role") != "client" or client_proof.get("local") != CLIENT or (
            client_proof.get("no_route") != self.isolation["no_route"]
        ):
            raise ValueError("client isolation evidence missing")
        self.active = capture_id
        self.events = {}
        self.transactions = {entry.id: entry for group in self.remaining[capture_id][1] for entry in group}
        self.recorder = Recorder(self.root, capture_id)

    def exchange(self, transaction_id, method, payload, endpoints, respond):
        started = utc_now()
        entry = self.transactions.get(transaction_id) if self.recorder is not None else None
        if entry is None or entry.method != method or entry.request != payload or transaction_id in self.events:
            raise ValueError("unexpected lab transaction")
        sleep(entry.delay_ms / 1000)
        respond(entry.response)
        self.events[entry.id] = event(entry, endpoints, started)

    def finish(self, capture_id):
        if self.recorder is None or capture_id != self.active:
            raise ValueError("unexpected capture finish")
        sleep(1.25)
        end = self.recorder.stop()
        start = self.recorder.start
        self.recorder = None
        spec, _ = self.remaining.pop(capture_id)
        write_new_object(self.root / f"evidence/{capture_id}-sensor.json", {
            "capture_id": capture_id, "isolation": self.isolation, "start": start, "end": end,
            "scenario": spec, "events": list(self.events.values()),
        })
        try:
            run_zeek(self.root, f"raw/{capture_id}.pcap", capture_id, self.zeek)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self.failure = error
            self.done.set()
            raise


def lab_handler(run, coordinator):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = TIMEOUT

        def do_GET(self):
            self.handle_request("get")

        def do_POST(self):
            self.handle_request("post")

        def log_message(self, *_args):
            pass

        def reply(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()

        def handle_request(self, method):
            try:
                if self.client_address[0] != CLIENT:
                    raise ValueError("unexpected lab peer")
                size = bounded_integer(int(self.headers.get("Content-Length", "0")), 0, 16_384)
                body = self.rfile.read(size)
                if coordinator:
                    if method != "post":
                        raise ValueError("expected local control request")
                    request = json.loads(body)
                    capture_id = identifier(request["capture_id"])
                    if self.path == "/start":
                        run.start(capture_id, request["isolation"])
                    elif self.path == "/finish":
                        run.finish(capture_id)
                    else:
                        raise ValueError("unexpected control request")
                    self.reply(b"ok")
                    if not run.remaining:
                        run.done.set()
                else:
                    prefix, transaction_id = self.path.rsplit("/", 1)
                    if prefix != "/lab":
                        raise ValueError("unexpected lab service path")
                    run.exchange(transaction_id, method, body, socket_endpoints(self.client_address[1], HTTP_PORT),
                                 self.reply)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
                print(f"Lab request failed: {error}", file=sys.stderr, flush=True)
                self.send_error(400)
    return Handler


def receive_udp(endpoint, run, stopped):
    while not stopped.is_set():
        try:
            data, peer = endpoint.recvfrom(1024)
        except TimeoutError:
            continue
        try:
            transaction_id, payload = data.split(b"\0", 1)
            if peer[0] != CLIENT:
                raise ValueError("unexpected UDP peer")
            run.exchange(transaction_id.decode("ascii"), "udp", payload, socket_endpoints(peer[1], UDP_PORT),
                         lambda body: endpoint.sendto(body, peer))
        except (OSError, ValueError) as error:
            print(f"Lab UDP request failed: {error}", file=sys.stderr, flush=True)


@contextmanager
def serve(server):
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield
    finally:
        server.shutdown()
        worker.join(timeout=2)


def run_sensor(root, sessions, route_checks, zeek):
    run = SensorRun(root, sessions, route_checks, zeek)
    for folder in ("raw", "evidence"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    stopped = Event()
    with (ThreadingHTTPServer((SENSOR, HTTP_PORT), lab_handler(run, False)) as app,
          ThreadingHTTPServer((SENSOR, CONTROL_PORT), lab_handler(run, True)) as coordinator,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp):
        udp.bind((SENSOR, UDP_PORT))
        udp.settimeout(0.25)
        worker = Thread(target=receive_udp, args=(udp, run, stopped), daemon=True)
        worker.start()
        try:
            with serve(app), serve(coordinator):
                print("G27_SENSOR_READY", flush=True)
                if not run.done.wait(300):
                    raise ValueError("bounded lab batch timed out")
                if run.failure is not None:
                    raise ValueError(f"offline Zeek failed: {run.failure}")
        finally:
            stopped.set()
            worker.join(timeout=2)
            if run.recorder is not None:
                run.recorder.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("sensor", "client"))
    parser.add_argument("plan", type=Path)
    parser.add_argument("routes", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("--zeek", default="/opt/zeek/bin/zeek")
    args = parser.parse_args()
    try:
        sessions, routes = plan(read_object(args.plan)), read_object(args.routes)
        if args.role == "sensor":
            run_sensor(args.root.resolve(), sessions, routes, args.zeek)
        else:
            run_client(args.root.resolve(), sessions, routes)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Lab collection stopped: {error}\n")


if __name__ == "__main__":
    main()
