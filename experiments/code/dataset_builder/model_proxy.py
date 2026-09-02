#!/usr/bin/env python3
"""Credential-holding fixed-destination proxy for poisoned agent runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="ASSA parent-only model proxy")
    parser.add_argument("--ready", required=True)
    parser.add_argument("--access-log", required=True)
    parser.add_argument("--upstream", default="https://openrouter.ai/api/v1/chat/completions")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--benign-static-response", action="store_true")
    args = parser.parse_args()
    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("model proxy requires OPENROUTER_API_KEY")
    ready = Path(args.ready).resolve()
    access_log = Path(args.access_log).resolve()
    access_log.parent.mkdir(parents=True, exist_ok=True)
    access_log.write_text("", encoding="utf-8")
    lock = threading.Lock()
    request_id = 0

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            nonlocal request_id
            started_wall = time.time_ns()
            started_mono = time.monotonic_ns()
            status = 502
            response_body = b""
            transport_error = None
            reasoning_disabled = False
            if self.path != "/chat/completions":
                status = 404
                response_body = b'{"error":"not found"}'
            else:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if args.benign_static_response:
                    status = 200
                    response_body = json.dumps({
                        "id": "assa-benign-sandbox-selftest",
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": "assa-benign-static",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "Benign sandbox self-test completed.",
                            },
                            "finish_reason": "stop",
                        }],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 5,
                            "total_tokens": 6,
                        },
                    }).encode("utf-8")
                else:
                    # Qwen3.x "thinking" models emit reasoning-only turns that a
                    # standard tool-use loop reads as a terminal empty assistant turn
                    # (content="", finish_reason="stop", no tool_call), ending the
                    # session before the agent acts. Disable thinking for Qwen so it
                    # surfaces content+tool_calls directly. No-op for every non-Qwen
                    # model (e.g. the frozen gemini generation) -> byte-identical.
                    upstream_body = body
                    reasoning_disabled = False
                    try:
                        parsed = json.loads(body)
                        model_name = str(parsed.get("model", "")).lower()
                        if "qwen" in model_name and parsed.get("reasoning") is None:
                            parsed["reasoning"] = {"enabled": False}
                            upstream_body = json.dumps(parsed).encode("utf-8")
                            reasoning_disabled = True
                    except (ValueError, TypeError):
                        upstream_body = body
                    request = urllib.request.Request(
                        args.upstream,
                        data=upstream_body,
                        method="POST",
                        headers={
                            "Authorization": "Bearer " + api_key,
                            "Content-Type": "application/json",
                            "User-Agent": "assa-parent-proxy/1",
                        },
                    )
                    try:
                        with urllib.request.urlopen(
                            request, timeout=args.timeout
                        ) as response:
                            status = int(response.status)
                            response_body = response.read()
                    except urllib.error.HTTPError as exc:
                        status = int(exc.code)
                        response_body = exc.read()
                    except Exception as exc:  # noqa: BLE001
                        transport_error = "%s: %s" % (type(exc).__name__, str(exc))
                        response_body = json.dumps({
                            "error": {
                                "message": "proxy transport failure: " + transport_error
                            }
                        }).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            with lock:
                request_id += 1
                row = {
                    "schema_version": "assa.model_proxy_access.v1",
                    "request_id": request_id,
                    "timestamp_start_realtime_ns": started_wall,
                    "timestamp_start_monotonic_ns": started_mono,
                    "timestamp_end_realtime_ns": time.time_ns(),
                    "timestamp_end_monotonic_ns": time.monotonic_ns(),
                    "client": list(self.client_address),
                    "path": self.path,
                    "status": status,
                    "request_body_sha256": hashlib.sha256(body).hexdigest() if self.path == "/chat/completions" else None,
                    "request_body_bytes": len(body) if self.path == "/chat/completions" else 0,
                    "response_bytes": len(response_body),
                    "credential_value_archived": False,
                    "transport_error": transport_error,
                    "upstream_request_enabled": not args.benign_static_response,
                }
                if reasoning_disabled:
                    row["reasoning_disabled_for_upstream"] = True
                with access_log.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())

        def log_message(self, _fmt: str, *_values: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    ready.parent.mkdir(parents=True, exist_ok=True)
    ready.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "base_url": f"http://127.0.0.1:{port}",
                "upstream": args.upstream,
                "benign_static_response": args.benign_static_response,
                "upstream_request_enabled": not args.benign_static_response,
                "access_log": str(access_log),
                "ready_realtime_ns": time.time_ns(),
                "ready_monotonic_ns": time.monotonic_ns(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    def stop(_signum: int, _frame: object) -> None:
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
