"""A small fake Ollama server on loopback, shared by tests.

Each test chooses how it answers, so every bad behaviour can be played for
real.
"""

import json
import socket
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODEL = "qwen3:8b"

Responder = Callable[[BaseHTTPRequestHandler, str, dict[str, Any] | None], None]


def send_json(handler: BaseHTTPRequestHandler, body: object, status: int = 200) -> None:
    data = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def chat_reply(content: object = "Hi.", **message: Any) -> dict[str, Any]:
    return {
        "model": MODEL,
        "message": {"role": "assistant", "content": content, **message},
        "done": True,
    }


class FakeOllama:
    """A loopback HTTP server whose answers each test chooses."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []
        self.respond: Responder = self._default
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                fake.requests.append((method, self.path, body))
                fake.respond(self, self.path, body)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def log_message(self, *args: object) -> None:
                pass

        server_class = ThreadingHTTPServer
        if ":" in host:

            class V6(ThreadingHTTPServer):
                address_family = socket.AF_INET6

            server_class = V6
        self.server = server_class((host, 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()

    @staticmethod
    def _default(handler: BaseHTTPRequestHandler, path: str, body: dict[str, Any] | None) -> None:
        if path == "/api/tags":
            send_json(handler, {"models": [{"name": MODEL}, {"name": "llama3:8b"}]})
        elif path == "/api/chat":
            send_json(handler, chat_reply())
        elif path == "/api/generate":
            send_json(handler, {"model": MODEL, "done": True, "done_reason": "unload"})
        else:
            send_json(handler, {"error": "not found"}, status=404)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
