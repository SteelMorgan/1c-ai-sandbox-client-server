#!/usr/bin/env python3
"""Tiny HTTP webhook to restart whitelisted Docker containers on the 1C VM.

Listens on $LISTEN_ADDR:$LISTEN_PORT. Authenticates with a Bearer token read
from $TOKEN_FILE. Accepts POST /restart/<container-name>; container name must
be in the whitelist defined by $ALLOWED_CONTAINERS (comma-separated).

No third-party dependencies — stdlib only.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8765"))
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/etc/onec-restart/token")
ALLOWED = [
    c.strip()
    for c in os.environ.get("ALLOWED_CONTAINERS", "onec-server,onec-web").split(",")
    if c.strip()
]
DOCKER_BIN = os.environ.get("DOCKER_BIN", "/usr/bin/docker")
RESTART_TIMEOUT = int(os.environ.get("RESTART_TIMEOUT", "60"))

NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

log = logging.getLogger("onec-restart")


def load_token() -> str:
    with open(TOKEN_FILE, "r", encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise RuntimeError(f"empty token in {TOKEN_FILE}")
    return token


class Handler(BaseHTTPRequestHandler):
    server_version = "onec-restart/1.0"
    expected_token: str = ""

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s - %s", self.client_address[0], fmt % args)

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not header.startswith(prefix):
            return False
        return hmac.compare_digest(header[len(prefix):].strip(), self.expected_token)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok", "allowed": ALLOWED})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._check_auth():
            self._send(401, {"error": "unauthorized"})
            return

        if not self.path.startswith("/restart/"):
            self._send(404, {"error": "not found"})
            return

        name = self.path[len("/restart/"):]
        if not NAME_RE.match(name):
            self._send(400, {"error": "invalid container name"})
            return
        if name not in ALLOWED:
            log.warning("rejected restart for %s (not in whitelist)", name)
            self._send(403, {"error": "container not allowed", "allowed": ALLOWED})
            return

        log.info("restarting container %s", name)
        try:
            proc = subprocess.run(
                [DOCKER_BIN, "restart", name],
                capture_output=True,
                text=True,
                timeout=RESTART_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            log.error("docker restart %s timed out", name)
            self._send(504, {"error": "docker restart timed out", "container": name})
            return

        if proc.returncode != 0:
            log.error("docker restart %s failed: %s", name, proc.stderr.strip())
            self._send(
                500,
                {
                    "error": "docker restart failed",
                    "container": name,
                    "stderr": proc.stderr.strip(),
                },
            )
            return

        self._send(200, {"status": "restarted", "container": name})


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    Handler.expected_token = load_token()
    log.info(
        "listening on %s:%d (allowed=%s)",
        LISTEN_ADDR, LISTEN_PORT, ",".join(ALLOWED),
    )
    server = ThreadingHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
