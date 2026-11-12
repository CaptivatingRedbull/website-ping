"""The web server the website-ping input checks. Standard library only.

Copied into a python image with docker compose cp. Logs one JSON line per
request to standard output, which the tests read with docker compose logs.
The log holds the authentication scheme of a request, never its credentials.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import sys
import threading
import time
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.request import parse_http_list, parse_keqv_list

CERTS = "/srv/certs"
TLS_PORTS = {8443: "valid", 8444: "expired", 8445: "self-signed", 8446: "wrong-host"}
MTLS_PORT = 8447
ANY_ROUTE_PORTS = frozenset({*TLS_PORTS, MTLS_PORT})
HTTP_PORT = 8080
SILENT_PORT = 8081

AUTH_USER = "wpuser"
AUTH_PASSWORD = "wpuser-secret"
AUTH_REALM = "wptest"
NONCE_LIFETIME = 300
MARKER_TEXT = "WPTEST-MARKER Grüße"
BIG_LIMIT = 5 * 1024 * 1024
SLOW_LIMIT_MS = 20000

_HTML = f"<html><body><p>{MARKER_TEXT}</p></body></html>\n"
_JSON = '{"marker": "' + MARKER_TEXT + '"}\n'
CONTENT_CASES: dict[str, tuple[str, bytes]] = {
    "utf8-charset": ("text/html; charset=utf-8", _HTML.encode("utf-8")),
    "latin1-charset": ("text/html; charset=iso-8859-1", _HTML.encode("latin-1")),
    "text-no-charset": ("text/html", _HTML.encode("latin-1")),
    "json-no-charset": ("application/json", _JSON.encode("utf-8")),
    "binary": ("application/octet-stream", bytes(range(256))),
}

_lock = threading.Lock()
_repeats: dict[str, int] = {}
_nonces: dict[str, float] = {}


def log(record: dict[str, object]) -> None:
    record["time"] = round(time.time(), 3)
    with _lock:
        sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
        sys.stdout.flush()


def client_cn(connection: object) -> str:
    """The common name of a verified client certificate, or an empty string."""
    if not isinstance(connection, ssl.SSLSocket):
        return ""
    certificate = connection.getpeercert()
    if not certificate:
        return ""
    subject = cast(
        "tuple[tuple[tuple[str, str], ...], ...]", certificate.get("subject", ())
    )
    names = [value for rdn in subject for key, value in rdn if key == "commonName"]
    return names[0] if names else ""


def big_body(size: int) -> bytes:
    return (b"0123456789" * (size // 10 + 1))[:size]


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def new_nonce() -> str:
    nonce = secrets.token_hex(16)
    now = time.monotonic()
    with _lock:
        for old in [
            n for n, issued in _nonces.items() if now - issued > NONCE_LIFETIME
        ]:
            del _nonces[old]
        _nonces[nonce] = now
    return nonce


def digest_challenge() -> str:
    return (
        f'Digest realm="{AUTH_REALM}", qop="auth", algorithm=MD5, '
        f'nonce="{new_nonce()}", opaque="wptest"'
    )


def digest_ok(header: str, method: str, path: str) -> bool:
    """RFC 7616 Digest with MD5 and qop=auth, for the fixed user and password."""
    scheme, _, rest = header.partition(" ")
    if scheme.lower() != "digest":
        return False
    fields = parse_keqv_list(parse_http_list(rest))
    nonce = fields.get("nonce", "")
    with _lock:
        issued = _nonces.get(nonce)
    if issued is None or time.monotonic() - issued > NONCE_LIFETIME:
        return False
    if (
        fields.get("username") != AUTH_USER
        or fields.get("realm") != AUTH_REALM
        or fields.get("uri") != path
        or fields.get("qop") != "auth"
        or fields.get("algorithm", "MD5").upper() != "MD5"
    ):
        return False
    ha1 = _md5(f"{AUTH_USER}:{AUTH_REALM}:{AUTH_PASSWORD}")
    ha2 = _md5(f"{method}:{path}")
    expected = _md5(
        f"{ha1}:{nonce}:{fields.get('nc', '')}:{fields.get('cnonce', '')}:auth:{ha2}"
    )
    return hmac.compare_digest(expected, fields.get("response", ""))


def basic_ok(header: str) -> bool:
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    return hmac.compare_digest(decoded, f"{AUTH_USER}:{AUTH_PASSWORD}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wptest-target"

    def log_message(self, format: str, *args: object) -> None:
        pass

    @property
    def port(self) -> int:
        return int(self.connection.getsockname()[1])

    def _log(self, status: int) -> None:
        record: dict[str, object] = {
            "port": self.port,
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "authorization": self.headers.get("Authorization", "").split(" ", 1)[0],
            "status": status,
        }
        if self.port == MTLS_PORT:
            record["client_cn"] = client_cn(self.connection)
        log(record)

    def _send(
        self,
        status: int,
        body: bytes = b"ok",
        headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        self._log(status)
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, status: int = 302) -> None:
        self._send(status, b"", [("Location", location)])

    def _unauthorized(self, challenges: Sequence[str]) -> None:
        self._send(
            401,
            b"unauthorized",
            [("WWW-Authenticate", challenge) for challenge in challenges],
        )

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
            elif self.port in ANY_ROUTE_PORTS:
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
            elif route == "content" and len(args) == 2 and args[0] in CONTENT_CASES:
                content_type, body = CONTENT_CASES[args[0]]
                self._send(200, body, [("Content-Type", content_type)])
            elif route == "big" and len(args) == 2:
                self._big(int(args[0]))
            elif route == "headers" and len(args) == 1:
                self._send(
                    200,
                    b"ok",
                    [
                        ("X-Wptest", "one"),
                        ("X-Wptest-Space", 'a b "c"'),
                        ("Set-Cookie", "a=1"),
                        ("Set-Cookie", "b=2"),
                    ],
                )
            elif route == "slow" and len(args) == 2:
                self._slow(int(args[0]))
            elif route == "auth" and len(args) == 2:
                self._auth(args[0])
            else:
                self._send(404, b"no such route")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _big(self, size: int) -> None:
        if not 0 <= size <= BIG_LIMIT:
            self._send(400, b"size out of range")
            return
        self._send(200, big_body(size), [("Content-Type", "text/plain; charset=utf-8")])

    def _slow(self, milliseconds: int) -> None:
        if not 0 <= milliseconds <= SLOW_LIMIT_MS:
            self._send(400, b"delay out of range")
            return
        time.sleep(milliseconds / 1000)
        self._send(200)

    def _auth(self, scheme: str) -> None:
        header = self.headers.get("Authorization", "")
        if scheme == "basic":
            if basic_ok(header):
                self._send(200, b"authenticated")
            else:
                self._unauthorized([f'Basic realm="{AUTH_REALM}"'])
        elif scheme == "digest":
            if digest_ok(header, self.command, self.path):
                self._send(200, b"authenticated")
            else:
                self._unauthorized([digest_challenge()])
        elif scheme == "ntlm":
            self._unauthorized(["NTLM", "Negotiate"])
        else:
            self._send(404, b"no such route")

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

    def get_request(self) -> tuple[socket.socket, Any]:
        """On a TLS port the handshake runs here. Log a failed one, such as no client cert."""
        try:
            return super().get_request()
        except ssl.SSLError as exc:
            log({"tls_error": exc.reason or str(exc), "port": self.server_address[1]})
            raise

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
        log(
            {
                "port": port,
                "method": "",
                "path": "",
                "user_agent": "",
                "authorization": "",
                "status": 0,
            }
        )
        timer = threading.Timer(60, connection.close)
        timer.daemon = True
        timer.start()


def tls_server(port: int, name: str, client_ca: str | None = None) -> Server:
    """A server with the named certificate; with client_ca, client certificates are required."""
    server = Server(("0.0.0.0", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{CERTS}/{name}.pem", f"{CERTS}/{name}.key")
    if client_ca is not None:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(client_ca)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve(server: Server) -> None:
    server.serve_forever()


def main() -> None:
    servers: list[Server] = [Server(("0.0.0.0", HTTP_PORT), Handler)]
    servers += [tls_server(port, name) for port, name in TLS_PORTS.items()]
    servers.append(tls_server(MTLS_PORT, "valid", client_ca=f"{CERTS}/ca.pem"))
    threads = [
        threading.Thread(target=serve, args=(server,), daemon=True)
        for server in servers
    ]
    threads.append(threading.Thread(target=silent, args=(SILENT_PORT,), daemon=True))
    for thread in threads:
        thread.start()
    log({"listening": [HTTP_PORT, SILENT_PORT, *TLS_PORTS, MTLS_PORT]})
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
