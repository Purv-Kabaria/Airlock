"""A tiny stdlib health server for stdio deployments.

The MCP server speaks stdio to its client, so `/healthz` and `/readyz` are served by a separate
threaded HTTP listener with no third-party dependency. `/readyz` gates on "a valid snapshot is
loaded and fresh" so an orchestrator never routes to a gateway that cannot decide (README §12).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from airlock.logging import get_logger

log = get_logger("airlock.mcp.health")


def start_health_server(host: str, port: int, ready: Callable[[], bool]) -> ThreadingHTTPServer:
    """Start `/healthz` (liveness) and `/readyz` (readiness) on a daemon thread. Returns the server."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._respond(200, "ok")
            elif self.path == "/readyz":
                self._respond(200, "ready") if ready() else self._respond(503, "not ready")
            else:
                self._respond(404, "not found")

        def _respond(self, code: int, body: str) -> None:
            payload = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_: object) -> None:
            return  # keep the health server quiet

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="airlock-health", daemon=True)
    thread.start()
    log.info("health.listening", host=host, port=port)
    return server
