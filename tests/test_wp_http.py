from __future__ import annotations

import http.client
import io
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from compat import override
from wp_deadline import Deadline
from wp_http import (
    DeadlineHTTPHandler,
    DeadlineHTTPSHandler,
    DeadlineSockets,
    LimitedRedirectHandler,
    order_headers,
    request_headers,
)
from wp_url import HostNameError


@dataclass(frozen=True)
class Seen:
    method: str
    path: str
    authorization: str


class Recorder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), RecordingHandler)
        self.seen: list[Seen] = []
        self.lock: threading.Lock = threading.Lock()

    @property
    def port(self) -> int:
        return self.server_address[1]


class RecordingHandler(BaseHTTPRequestHandler):
    """/code/<n>: n redirect to /done; /chain/<k>: k redirects; /loop: forever;
    /to-localhost: 302 to the same server as localhost (another host name)."""

    def do_GET(self) -> None:
        self._answer()

    def do_HEAD(self) -> None:
        self._answer()

    def _answer(self) -> None:
        recorder = cast(Recorder, self.server)
        with recorder.lock:
            recorder.seen.append(
                Seen(self.command, self.path, self.headers.get("Authorization", ""))
            )
        parts = self.path.strip("/").split("/")
        if parts[0] == "code":
            self._redirect(int(parts[1]), "/done")
        elif parts[0] == "chain" and int(parts[1]) > 0:
            self._redirect(302, f"/chain/{int(parts[1]) - 1}")
        elif parts[0] == "loop":
            self._redirect(302, "/loop")
        elif parts[0] == "to-localhost":
            port = cast(Recorder, self.server).port
            self._redirect(302, f"http://localhost:{port}/done")
        elif parts[0] == "to-unicode":
            # UTF-8 bytes; send_header writes the value as Latin-1.
            self._redirect(302, "/M\xc3\xbcller")
        elif parts[0] == "to-eszett":
            self._redirect(302, "http://stra\xc3\x9fe.test/")
        elif parts[0] == "no-location":
            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            if self.command != "HEAD":
                _ = self.wfile.write(b"ok")

    def _redirect(self, code: int, location: str) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[Recorder]:
    recorder = Recorder()
    threading.Thread(target=recorder.serve_forever, daemon=True).start()
    yield recorder
    recorder.shutdown()
    recorder.server_close()


def fetch(
    server: Recorder,
    path: str,
    limit: int,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, LimitedRedirectHandler]:
    handler = LimitedRedirectHandler(limit)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), handler)
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.port}{path}", headers=headers or {}, method=method
    )
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, handler
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, handler


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_every_redirect_code_is_followed_with_get(server: Recorder, code: int) -> None:
    status, handler = fetch(server, f"/code/{code}", 5)
    assert (status, handler.followed, handler.limit_reached) == (200, 1, False)
    assert [(s.method, s.path) for s in server.seen] == [
        ("GET", f"/code/{code}"),
        ("GET", "/done"),
    ]


@pytest.mark.parametrize("code", [303, 307, 308])
def test_head_stays_head(server: Recorder, code: int) -> None:
    status, _ = fetch(server, f"/code/{code}", 5, method="HEAD")
    assert status == 200
    assert [s.method for s in server.seen] == ["HEAD", "HEAD"]


def test_chain_of_50_within_a_limit_of_50(server: Recorder) -> None:
    status, handler = fetch(server, "/chain/50", 50)
    assert (status, handler.followed, handler.limit_reached) == (200, 50, False)
    assert len(server.seen) == 51


def test_chain_of_51_over_a_limit_of_50(server: Recorder) -> None:
    status, handler = fetch(server, "/chain/51", 50)
    assert (status, handler.followed, handler.limit_reached) == (302, 50, True)
    assert len(server.seen) == 51


def test_loop_runs_into_the_limit(server: Recorder) -> None:
    status, handler = fetch(server, "/loop", 10)
    assert (status, handler.limit_reached) == (302, True)
    assert len(server.seen) == 11


def test_limit_zero_returns_the_first_redirect(server: Recorder) -> None:
    status, handler = fetch(server, "/code/302", 0)
    assert (status, handler.followed, handler.limit_reached) == (302, 0, True)
    assert len(server.seen) == 1


def test_redirect_without_location_is_the_result(server: Recorder) -> None:
    status, handler = fetch(server, "/no-location", 5)
    assert (status, handler.limit_reached) == (302, False)


def test_authorization_kept_on_the_same_host(server: Recorder) -> None:
    _ = fetch(server, "/code/302", 5, headers={"Authorization": "Basic eDp5"})
    assert [s.authorization for s in server.seen] == ["Basic eDp5", "Basic eDp5"]


def test_authorization_dropped_on_another_host(server: Recorder) -> None:
    status, _ = fetch(
        server, "/to-localhost", 5, headers={"Authorization": "Basic eDp5"}
    )
    assert status == 200
    assert [s.authorization for s in server.seen] == ["Basic eDp5", ""]


def test_location_is_percent_encoded_as_utf8(server: Recorder) -> None:
    status, _ = fetch(server, "/to-unicode", 5)
    assert status == 200
    assert [s.path for s in server.seen] == ["/to-unicode", "/M%C3%BCller"]


def test_location_with_refused_host_raises(server: Recorder) -> None:
    with pytest.raises(HostNameError):
        _ = fetch(server, "/to-eszett", 5)
    assert len(server.seen) == 1


def test_new_request_copies_headers_except_content_and_host() -> None:
    handler = LimitedRedirectHandler(5)
    original = urllib.request.Request(
        "http://a.test/x",
        headers={
            "User-Agent": "ua",
            "Content-Type": "text/plain",
            "Content-Length": "3",
            "Host": "a.test",
            "X-Custom": "1",
        },
    )
    new = handler.redirect_request(
        original,
        io.BytesIO(),
        307,
        "Temporary Redirect",
        HTTPMessage(),
        "http://a.test/y",
    )
    assert new is not None
    assert new.full_url == "http://a.test/y" and new.get_method() == "GET"
    assert new.unverifiable and new.origin_req_host == original.origin_req_host
    assert sorted(new.header_items()) == [("User-agent", "ua"), ("X-custom", "1")]
    assert new.data is None


def test_request_headers() -> None:
    assert list(request_headers("ua").items()) == [
        ("User-Agent", "ua"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept", "*/*"),
    ]


def test_order_headers_puts_hop_only_headers_last() -> None:
    headers = {"X-Custom": "1", **request_headers("ua")}
    request = urllib.request.Request("http://a.test/", headers=headers)
    request.add_unredirected_header("Cookie", "a=1")
    request.add_unredirected_header("Host", "a.test")
    request.add_unredirected_header("Authorization", "Basic eDp5")
    before = dict(request.headers)
    order_headers(request)
    assert list(request.unredirected_hdrs.items()) == [
        ("Host", "a.test"),
        ("User-agent", "ua"),
        ("Accept-encoding", "gzip, deflate"),
        ("Accept", "*/*"),
        ("Connection", "close"),
        ("X-custom", "1"),
        ("Cookie", "a=1"),
        ("Authorization", "Basic eDp5"),
    ]
    assert request.headers == before


def test_other_methods_are_not_followed() -> None:
    handler = LimitedRedirectHandler(5)
    original = urllib.request.Request("http://a.test/x", data=b"x", method="POST")
    with pytest.raises(urllib.error.HTTPError):
        _ = handler.redirect_request(
            original, io.BytesIO(), 302, "Found", HTTPMessage(), "http://a.test/y"
        )
    assert handler.followed == 0


# ---- deadline -----------------------------------------------------------------


class StallServer:
    """Loopback server that answers every request by stalling: either before the
    status line ("headers") or after the headers of a 100-byte body ("body")."""

    def __init__(self, stall: str, tls: tuple[Path, Path] | None = None) -> None:
        self.stall: str = stall
        self.context: ssl.SSLContext | None = None
        if tls is not None:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(str(tls[0]), str(tls[1]))
        self.listener: socket.socket = socket.create_server(("127.0.0.1", 0))
        self.stop: threading.Event = threading.Event()
        self.port: int = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self) -> str:
        scheme = "https" if self.context else "http"
        return f"{scheme}://127.0.0.1:{self.port}/"

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            if self.stall == "body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
            _ = self.stop.wait(30)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()


def client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def deadline_opener(deadline: Deadline) -> urllib.request.OpenerDirector:
    sockets = DeadlineSockets(deadline)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        DeadlineHTTPHandler(sockets),
        DeadlineHTTPSHandler(sockets, client_context),
    )


def expire_later(deadline: Deadline, seconds: float) -> threading.Timer:
    """Stands in for the runner's tick, which expires overdue deadlines."""
    timer = threading.Timer(seconds, deadline.expire)
    timer.start()
    return timer


def test_timeout_is_the_time_left_at_most_the_configured_one() -> None:
    now = [100.0]
    sockets = DeadlineSockets(Deadline(110.0, clock=lambda: now[0]))
    assert sockets.timeout(30) == 10.0
    assert sockets.timeout(5) == 5
    assert sockets.timeout(None) == 10.0
    now[0] = 109.5
    assert sockets.timeout(30) == 0.5


def test_no_connection_once_the_deadline_passed() -> None:
    sockets = DeadlineSockets(Deadline(10.0, clock=lambda: 10.0))
    with pytest.raises(socket.timeout):
        _ = sockets.timeout(30)


def test_socket_added_after_expiry_is_shut_down_at_once() -> None:
    deadline = Deadline.after(30)
    sockets = DeadlineSockets(deadline)
    deadline.expire()
    a, b = socket.socketpair()
    with a, b:
        sockets.add(a)
        a.settimeout(5)
        assert a.recv(1) == b""


def test_tighten_bounds_the_next_read_and_skips_closed_sockets() -> None:
    sockets = DeadlineSockets(Deadline.after(2))
    a, b = socket.socketpair()
    closed, partner = socket.socketpair()
    closed.close()
    with a, b, partner:
        sockets.add(a)
        sockets.add(closed)
        sockets.tighten()
        timeout = a.gettimeout()
        assert timeout is not None and 0 < timeout <= 2


@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
def test_expire_ends_a_body_read_in_another_thread(
    tls_files: tuple[Path, Path], tls: bool
) -> None:
    server = StallServer("body", tls_files if tls else None)
    deadline = Deadline.after(30)
    try:
        with deadline_opener(deadline).open(server.url, timeout=30) as response:
            assert response.read1(10) == b"x"
            timer = expire_later(deadline, 0.3)
            start = time.monotonic()
            try:
                rest = response.read1(10)
            except (OSError, ValueError):
                rest = b""
            timer.join()
            assert rest == b""
            assert time.monotonic() - start < 2
    finally:
        server.close()


@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
def test_expire_ends_the_wait_for_the_status_line(
    tls_files: tuple[Path, Path], tls: bool
) -> None:
    server = StallServer("headers", tls_files if tls else None)
    deadline = Deadline.after(30)
    timer = expire_later(deadline, 0.3)
    start = time.monotonic()
    try:
        with pytest.raises((OSError, http.client.HTTPException)):
            _ = deadline_opener(deadline).open(server.url, timeout=30)
        assert time.monotonic() - start < 2
    finally:
        timer.join()
        server.close()


def test_connection_waits_only_for_the_time_left() -> None:
    server = StallServer("headers")
    start = time.monotonic()
    try:
        with pytest.raises(OSError):
            _ = deadline_opener(Deadline.after(0.5)).open(server.url, timeout=30)
        assert 0.4 < time.monotonic() - start < 1.5
    finally:
        server.close()
