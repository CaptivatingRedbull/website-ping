"""The web server the website-ping input checks. Standard library only.

Copied into a python image with docker compose cp. Logs one JSON line per
request to standard output, which the tests read with docker compose logs.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERTS = "/srv/certs"
TLS_PORTS = {8443: "valid", 8444: "expired", 8445: "self-signed", 8446: "wrong-host"}
HTTP_PORT = 8080
SILENT_PORT = 8081

_lock = threading.Lock()
_repeats: dict[str, int] = {}


def log(record: dict[str, object]) -> None:
    record["time"] = round(time.time(), 3)
    with _lock:
        sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
        sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wptest-target"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _log(self, status: int) -> None:
        log(
            {
                "port": self.connection.getsockname()[1],
                "path": self.path,
                "user_agent": self.headers.get("User-Agent", ""),
                "status": status,
            }
        )

    def _send(
        self, status: int, body: bytes = b"ok", headers: dict[str, str] | None = None
    ) -> None:
        self._log(status)
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, status: int = 302) -> None:
        self._send(status, b"", {"Location": location})

    def do_GET(self) -> None:
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        route, args = parts[0], parts[1:]
        try:
            if route == "__reset":
                with _lock:
                    _repeats.clear()
                log({"mark": True})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            elif self.connection.getsockname()[1] in TLS_PORTS:
                self._send(200)
            elif route == "status" and len(args) == 1:
                self._send(int(args[0]))
            elif route == "chain" and len(args) == 2:
                title, remaining = args[0], int(args[1])
                if remaining > 0:
                    self._redirect(f"/chain/{title}/{remaining - 1}")
                else:
                    self._send(200)
            elif route == "repeat" and len(args) == 2:
                title, limit = args[0], int(args[1])
                with _lock:
                    seen = _repeats.get(title, 0)
                    _repeats[title] = seen + 1
                if seen < limit:
                    self._redirect(f"/repeat/{title}/{limit}")
                else:
                    self._send(200)
            elif route == "loop" and len(args) == 1:
                self._redirect(f"/loop/{args[0]}")
            elif route == "redirect" and len(args) == 2:
                self._redirect(f"/done/{args[1]}", int(args[0]))
            elif route == "done" and len(args) == 1:
                self._send(200)
            elif route == "slow-body" and len(args) == 1:
                self._partial_body(1024, [(0, 16)], stall=30)
            elif route == "trickle" and len(args) == 1:
                self._partial_body(64, [(1, 4)] * 16, stall=0)
            else:
                self._send(404, b"no such route")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _partial_body(
        self, length: int, steps: list[tuple[float, int]], stall: float
    ) -> None:
        """Send headers, then (delay, byte count) steps, then stall and close."""
        self._log(200)
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.end_headers()
        self.wfile.flush()
        for delay, count in steps:
            time.sleep(delay)
            self.wfile.write(b"x" * count)
            self.wfile.flush()
        time.sleep(stall)
        self.close_connection = True


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        """A client that drops the connection is normal here. Log one JSON line."""
        log(
            {"connection_error": str(sys.exc_info()[1]), "port": self.server_address[1]}
        )


def silent(port: int) -> None:
    """Accept connections and never answer. Each is closed after 60 seconds."""
    listener = socket.create_server(("0.0.0.0", port))
    while True:
        connection, _ = listener.accept()
        log({"port": port, "path": "", "user_agent": "", "status": 0})
        timer = threading.Timer(60, connection.close)
        timer.daemon = True
        timer.start()


def serve(server: Server) -> None:
    server.serve_forever()


def main() -> None:
    servers: list[Server] = [Server(("0.0.0.0", HTTP_PORT), Handler)]
    for port, name in TLS_PORTS.items():
        server = Server(("0.0.0.0", port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(f"{CERTS}/{name}.pem", f"{CERTS}/{name}.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
    threads = [
        threading.Thread(target=serve, args=(server,), daemon=True)
        for server in servers
    ]
    threads.append(threading.Thread(target=silent, args=(SILENT_PORT,), daemon=True))
    for thread in threads:
        thread.start()
    log({"listening": [HTTP_PORT, SILENT_PORT, *TLS_PORTS]})
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
