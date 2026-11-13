"""The web server the website-ping input checks. Standard library only.

Copied into a python image with docker compose cp. Logs one JSON line per
request to standard output, which the tests read with docker compose logs.
The log holds the authentication scheme of a request, never its credentials.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import sys
import threading
import time
import zlib
from collections.abc import Mapping, Sequence
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

ENCODED_BODY = _HTML.encode("utf-8")
ENCODED_CONTENT_TYPE = "text/html; charset=utf-8"
COOKIE_NAME = "wptest_session"
COOKIE_VALUE = "ok"
BODY_LINES = (
    "WPTEST-MARKER first line\n"
    "second line\n"
    "2021-03-04T05:06:07Z third line starts with a date\n"
    "fourth line\n"
    "fifth line\n"
).encode("ascii")
BODY_BINARY = (
    b"WPTEST-MARKER nul \x00 vt \x0b us \x1f invalid utf-8 \xff\xfe \xc3\x28 end\n"
)

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


def gzip_body(body: bytes) -> bytes:
    """gzip with a fixed header time, so the bytes are the same on every request."""
    return gzip.compress(body, mtime=0)


def deflate_body(body: bytes, raw: bool) -> bytes:
    """Content-Encoding deflate: zlib-wrapped as RFC 9110 says, or raw as some servers send."""
    wbits = -zlib.MAX_WBITS if raw else zlib.MAX_WBITS
    compressor = zlib.compressobj(wbits=wbits)
    return compressor.compress(body) + compressor.flush()


def accepts_gzip(header: str) -> bool:
    codings = [part.split(";", 1)[0].strip().lower() for part in header.split(",")]
    return "gzip" in codings


def cookie_names(header: str) -> str:
    """The cookie names of a Cookie header in the order sent, never their values."""
    names = [part.split("=", 1)[0].strip() for part in header.split(";")]
    return ",".join(name for name in names if name)


def has_cookie(header: str, name: str, value: str) -> bool:
    pairs = [part.strip().split("=", 1) for part in header.split(";")]
    return [name, value] in pairs


def request_line(raw: bytes) -> str:
    """The request line as received, decoded as Latin-1 so every byte maps to one
    character: line.encode("latin-1") gives the original bytes back."""
    return raw.rstrip(b"\r\n").decode("latin-1")


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


ENCODED_ROUTES = frozenset({"gzip", "gzip-forced", "deflate", "deflate-raw"})
EMPTY_REQUEST: Mapping[str, object] = {
    "method": "",
    "path": "",
    "user_agent": "",
    "authorization": "",
    "status": 0,
    "host": "",
    "accept": "",
    "accept_encoding": "",
    "connection": "",
    "cookie": "",
    "header_names": [],
}
"""Every key of a request log record, for records with no parsed request."""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "wptest-target"
    raw_requestline: bytes
    """Set by http.server before parse_request; not declared in its type stubs."""

    def log_message(self, format: str, *args: object) -> None:
        pass

    @property
    def port(self) -> int:
        return int(self.connection.getsockname()[1])

    def _log(self, status: int, with_request_line: bool = False) -> None:
        record: dict[str, object] = {
            "port": self.port,
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "authorization": self.headers.get("Authorization", "").split(" ", 1)[0],
            "status": status,
            "host": self.headers.get("Host", ""),
            "accept": self.headers.get("Accept", ""),
            "accept_encoding": self.headers.get("Accept-Encoding", ""),
            "connection": self.headers.get("Connection", ""),
            "cookie": cookie_names(self.headers.get("Cookie", "")),
            "header_names": list(self.headers.keys()),
        }
        if with_request_line:
            record["request_line"] = request_line(self.raw_requestline)
        if self.port == MTLS_PORT:
            record["client_cn"] = client_cn(self.connection)
        log(record)

    def parse_request(self) -> bool:
        """Log a request line that http.server rejects, such as one with a raw space
        in the path. The error response has already been sent."""
        if super().parse_request():
            return True
        line = request_line(self.raw_requestline)
        words = line.split(" ")
        log(
            {
                **EMPTY_REQUEST,
                "port": self.port,
                "method": words[0] if len(words) > 1 else "",
                "path": " ".join(words[1:-1]),
                "status": 400,
                "request_line": line,
                "rejected": True,
            }
        )
        return False

    def _send(
        self,
        status: int,
        body: bytes = b"ok",
        headers: Sequence[tuple[str, str]] = (),
        with_request_line: bool = False,
    ) -> None:
        self._log(status, with_request_line)
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
            elif route in ENCODED_ROUTES and len(args) == 1:
                self._encoded(route)
            elif route == "cookie" and len(args) == 1:
                self._cookie(args[0])
            elif route == "path" and len(args) >= 1:
                self._send(200, with_request_line=True)
            elif route == "body-lines" and len(args) == 1:
                self._send(
                    200, BODY_LINES, [("Content-Type", "text/plain; charset=utf-8")]
                )
            elif route == "body-binary" and len(args) == 1:
                self._send(
                    200, BODY_BINARY, [("Content-Type", "text/plain; charset=utf-8")]
                )
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

    def _encoded(self, route: str) -> None:
        """The same HTML body, compressed as the route says. gzip/ compresses only
        when the request accepts gzip; the others always compress."""
        headers = [("Content-Type", ENCODED_CONTENT_TYPE)]
        if route == "gzip" and not accepts_gzip(
            self.headers.get("Accept-Encoding", "")
        ):
            self._send(200, ENCODED_BODY, headers)
            return
        if route in ("gzip", "gzip-forced"):
            body, coding = gzip_body(ENCODED_BODY), "gzip"
        else:
            body = deflate_body(ENCODED_BODY, raw=route == "deflate-raw")
            coding = "deflate"
        self._send(200, body, [*headers, ("Content-Encoding", coding)])

    def _cookie(self, title: str) -> None:
        """200 with the session cookie; without it, set it and redirect to the same URL."""
        if has_cookie(self.headers.get("Cookie", ""), COOKIE_NAME, COOKIE_VALUE):
            self._send(200, b"cookie ok")
            return
        self._send(
            302,
            b"",
            [
                ("Set-Cookie", f"{COOKIE_NAME}={COOKIE_VALUE}; Path=/"),
                ("Location", f"/cookie/{title}"),
            ],
        )

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
        log({**EMPTY_REQUEST, "port": port})
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
