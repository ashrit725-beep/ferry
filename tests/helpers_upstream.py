"""TEST DOUBLE ONLY: a fake OpenAI-compatible inference server modelled on llama-server.

This is not an inference server and must never be used outside the test suite.
It listens on 127.0.0.1 on a random port (stdlib ThreadingHTTPServer in a daemon
thread), records every request it receives (so tests can prove that denied
requests never reached it), and can be told to be slow, fail, report another
model file, or drop a stream half way.

Behaviour copied from a real llama-server (build b11669-620d2225c):
- GET /health needs no auth and returns {"status": "ok"} (503 while loading).
- GET /v1/models and GET /props need the bearer token (401 otherwise).
- /props reports model_path, model_alias and build_info.
- The "model" field of a completion request is ignored; answers name the alias.
- Streams are `data: {...}` lines, a final chunk with `choices: []` and `usage`
  (when stream_options.include_usage is set), then `data: [DONE]`.
For Ollama-kind health checks it also answers GET /api/version and /api/tags.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

FAKE_BUILD_INFO = "b11669-620d2225c"


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str]
    """Lower-cased header names."""
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True


class FakeUpstream:
    """Configure by assigning attributes, also while it runs."""

    def __init__(self, *, token: str | None = "upstream-test-token", model_alias: str = "fake-alias",
                 model_path: str = "/models/not-in-the-store.gguf", build_info: str = FAKE_BUILD_INFO,
                 completion_text: str = "The quick brown fox.") -> None:
        self.token = token
        self.model_alias = model_alias
        self.model_path = model_path
        self.build_info = build_info
        self.completion_text = completion_text
        self.prompt_tokens = 11
        self.health_status = 200
        self.props_status = 200
        self.chat_status: int | None = None
        """When set, chat completions answer with this HTTP status and an error body."""
        self.chat_error_message = "simulated backend failure"
        self.delay_s = 0.0
        """Sleep before answering a chat completion (to provoke gateway timeouts)."""
        self.chunk_delay_s = 0.0
        self.drop_mid_stream = False
        """Close the socket after two content chunks, without ending the chunked body."""
        self.send_done = True
        self.set_cookie: str | None = None
        """When set, chat completion answers carry this Set-Cookie header."""
        self.ollama_version = "0.12.6"
        self._requests: list[RecordedRequest] = []
        self._lock = threading.Lock()
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    # --- lifecycle ---

    def start(self) -> FakeUpstream:
        self._server = _Server(("127.0.0.1", 0), _handler_for(self))
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
                                        name="fake-upstream", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = self._thread = None

    def __enter__(self) -> FakeUpstream:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def port(self) -> int:
        assert self._server is not None, "FakeUpstream is not running"
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # --- request log ---

    def record(self, request: RecordedRequest) -> None:
        with self._lock:
            self._requests.append(request)

    @property
    def requests(self) -> list[RecordedRequest]:
        with self._lock:
            return list(self._requests)

    def chat_requests(self) -> list[RecordedRequest]:
        return [r for r in self.requests if r.path.startswith("/v1/chat/completions")]

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()

    # --- canned answers ---

    def pieces(self) -> list[str]:
        words = self.completion_text.split(" ")
        return [w if i == 0 else " " + w for i, w in enumerate(words)]

    def usage(self) -> dict[str, int]:
        completion = len(self.pieces())
        return {"prompt_tokens": self.prompt_tokens, "completion_tokens": completion,
                "total_tokens": self.prompt_tokens + completion}


def _handler_for(upstream: FakeUpstream) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "fake-llama-server/test-double"

        def log_message(self, format: str, *args: Any) -> None:
            pass  # keep pytest output clean

        def handle(self) -> None:
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass  # the gateway hung up, e.g. after its client went away

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def _record(self, body: bytes) -> None:
            upstream.record(RecordedRequest(self.command, self.path,
                                            {k.lower(): v for k, v in self.headers.items()}, body))

        def _authorized(self) -> bool:
            return upstream.token is None or self.headers.get("Authorization") == f"Bearer {upstream.token}"

        def _json(self, status: int, obj: Any) -> None:
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            if upstream.set_cookie and self.path == "/v1/chat/completions":
                self.send_header("Set-Cookie", upstream.set_cookie)
            self.end_headers()
            self.wfile.write(data)

        def _unauthorized(self) -> None:
            self._json(401, {"error": {"code": 401, "message": "Invalid API Key", "type": "authentication_error"}})

        def do_GET(self) -> None:
            self._record(b"")
            try:
                if self.path == "/health":
                    if upstream.health_status == 200:
                        self._json(200, {"status": "ok"})
                    else:
                        self._json(upstream.health_status, {"error": {"code": upstream.health_status,
                                                                      "message": "Loading model",
                                                                      "type": "unavailable_error"}})
                elif self.path in ("/v1/models", "/props"):
                    if not self._authorized():
                        self._unauthorized()
                    elif self.path == "/v1/models":
                        self._json(200, {"object": "list", "data": [
                            {"id": upstream.model_alias, "object": "model", "created": 1761616380,
                             "owned_by": "llamacpp", "meta": {"n_params": 494032768}}]})
                    elif upstream.props_status != 200:
                        self._json(upstream.props_status, {"error": {"code": upstream.props_status,
                                                                     "message": "props unavailable"}})
                    else:
                        self._json(200, {"model_path": upstream.model_path, "model_alias": upstream.model_alias,
                                         "build_info": upstream.build_info, "total_slots": 1,
                                         "default_generation_settings": {"n_ctx": 4096}})
                elif self.path == "/api/version":
                    self._json(200, {"version": upstream.ollama_version})
                elif self.path == "/api/tags":
                    self._json(200, {"models": [{"name": upstream.model_alias, "model": upstream.model_alias,
                                                 "digest": "0" * 64, "size": 1}]})
                else:
                    self._json(404, {"error": {"code": 404, "message": "File Not Found", "type": "not_found_error"}})
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self) -> None:
            body = self._body()
            self._record(body)
            try:
                if self.path != "/v1/chat/completions":
                    self._json(404, {"error": {"code": 404, "message": "File Not Found", "type": "not_found_error"}})
                    return
                if not self._authorized():
                    self._unauthorized()
                    return
                if upstream.delay_s:
                    time.sleep(upstream.delay_s)
                if upstream.chat_status is not None:
                    self._json(upstream.chat_status, {"error": {"code": upstream.chat_status,
                                                                "message": upstream.chat_error_message,
                                                                "type": "server_error"}})
                    return
                request = json.loads(body or b"{}")
                if request.get("stream"):
                    self._stream(request)
                else:
                    self._json(200, {
                        "id": "chatcmpl-fake", "object": "chat.completion", "created": int(time.time()),
                        "model": upstream.model_alias, "system_fingerprint": upstream.build_info,
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": upstream.completion_text}}],
                        "usage": upstream.usage()})
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _chunk(self, data: bytes) -> None:
            self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")
            self.wfile.flush()

        def _event(self, obj: Any) -> None:
            self._chunk(b"data: " + json.dumps(obj).encode("utf-8") + b"\n\n")

        def _stream(self, request: dict[str, Any]) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            base = {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "created": int(time.time()),
                    "model": upstream.model_alias, "system_fingerprint": upstream.build_info}
            self._event({**base, "choices": [{"index": 0, "finish_reason": None,
                                              "delta": {"role": "assistant", "content": None}}]})
            for i, piece in enumerate(upstream.pieces()):
                if upstream.drop_mid_stream and i == 2:
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                if upstream.chunk_delay_s:
                    time.sleep(upstream.chunk_delay_s)
                self._event({**base, "choices": [{"index": 0, "finish_reason": None, "delta": {"content": piece}}]})
            self._event({**base, "choices": [{"index": 0, "finish_reason": "stop", "delta": {}}]})
            if (request.get("stream_options") or {}).get("include_usage"):
                self._event({**base, "choices": [], "usage": upstream.usage()})
            if upstream.send_done:
                self._chunk(b"data: [DONE]\n\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    return Handler
