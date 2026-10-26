"""Minimal webhook receiver for the latency benchmark: answers 204, stores nothing.

Sentinel records when each delivery completed, so the benchmark measures latency from
the database (``completed_at - event.created_at``); the receiver only has to be fast.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return  # keep the benchmark free of per-request logging


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104
