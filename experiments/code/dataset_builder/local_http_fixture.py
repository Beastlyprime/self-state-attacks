#!/usr/bin/env python3
"""Serve one paired external-content artifact over loopback HTTP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve one offline source fixture")
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--access-log", required=True)
    args = parser.parse_args()

    artifact = Path(args.artifact).resolve()
    ready = Path(args.ready).resolve()
    access_log = Path(args.access_log).resolve()
    access_log.parent.mkdir(parents=True, exist_ok=True)
    access_log.write_text("", encoding="utf-8")
    body = artifact.read_bytes()
    log_lock = threading.Lock()
    request_counter = 0
    artifact_sha256 = hashlib.sha256(body).hexdigest()

    def log_access(
        handler: BaseHTTPRequestHandler,
        status: int,
        response_bytes: int,
        started_wall_ns: int,
        started_monotonic_ns: int,
    ) -> None:
        nonlocal request_counter
        with log_lock:
            request_counter += 1
            row = {
                "schema_version": "assa.fixture_http_access.v1",
                "request_id": request_counter,
                "timestamp_realtime_ns": started_wall_ns,
                "timestamp_monotonic_ns": started_monotonic_ns,
                "timestamp_end_realtime_ns": time.time_ns(),
                "timestamp_end_monotonic_ns": time.monotonic_ns(),
                "server_pid": os.getpid(),
                "server_process_start_time_ticks": int(
                    Path("/proc/self/stat")
                    .read_text(encoding="utf-8")
                    .rsplit(")", 1)[1]
                    .split()[19]
                ),
                "client_ip": handler.client_address[0],
                "client_port": handler.client_address[1],
                "server_ip": handler.server.server_address[0],
                "server_port": handler.server.server_address[1],
                "method": handler.command,
                "path": handler.path,
                "status": status,
                "response_bytes": response_bytes,
                "artifact_sha256": artifact_sha256,
            }
            with access_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            started_wall_ns = time.time_ns()
            started_monotonic_ns = time.monotonic_ns()
            if self.path != "/artifact.txt":
                self.send_error(404)
                log_access(
                    self, 404, 0, started_wall_ns, started_monotonic_ns
                )
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            log_access(
                self, 200, len(body), started_wall_ns, started_monotonic_ns
            )

        def log_message(self, fmt: str, *values: object) -> None:
            print(fmt % values, flush=True)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "port": port,
                "url": f"http://127.0.0.1:{port}/artifact.txt",
                "artifact": str(artifact),
                "bytes": len(body),
                "access_log": str(access_log),
                "ready_wall_ns": time.time_ns(),
                "ready_monotonic_ns": time.monotonic_ns(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    def stop(_signum: int, _frame: object) -> None:
        # ``shutdown`` cannot be called synchronously from serve_forever's
        # own thread, so make the signal cause the loop to return instead.
        server._BaseServer__shutdown_request = True  # type: ignore[attr-defined]

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
