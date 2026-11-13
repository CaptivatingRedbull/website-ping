import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import pytest
from compat import override
from ping_check import CheckResult, check_url, event_fields
from ping_config import Settings, build_settings


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            self._send(200, b"hello")
        elif self.path == "/missing":
            self._send(404, b"nope")
        elif self.path.startswith("/redir/"):
            hops = int(self.path.rsplit("/", 1)[1])
            if hops == 0:
                self._send(200, b"end")
            else:
                self.send_response(301)
                self.send_header("Location", f"/redir/{hops - 1}")
                self.send_header("Content-Length", "0")
                self.end_headers()
        elif self.path == "/hang":
            time.sleep(3)
            self._send(200, b"late")
        else:
            self._send(500, b"boom")

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        _ = self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def make(url: str, **extra: str) -> Settings:
    settings, _ = build_settings(
        "web_ping://test", {"url": url, "interval": "60", **extra}
    )
    return settings


def test_ok(base_url: str) -> None:
    r = check_url(make(base_url + "/ok"))
    assert (r.response_code, r.timed_out, r.error) == (200, False, "")


def test_404_is_a_result_not_an_error(base_url: str) -> None:
    r = check_url(make(base_url + "/missing"))
    assert (r.response_code, r.error) == (404, "")


def test_redirects_are_followed(base_url: str) -> None:
    assert (
        check_url(make(base_url + "/redir/3", max_redirects="5")).response_code == 200
    )


def test_redirect_limit(base_url: str) -> None:
    r = check_url(make(base_url + "/redir/5", max_redirects="2"))
    assert r.response_code == 301
    assert "redirect limit" in r.error


def test_zero_redirects_allowed(base_url: str) -> None:
    assert (
        check_url(make(base_url + "/redir/1", max_redirects="0")).response_code == 301
    )


def test_timeout(base_url: str) -> None:
    r = check_url(make(base_url + "/hang", timeout="1"))
    assert r.timed_out and r.response_code == 0
    assert r.total_time < 2.5


def test_connection_refused() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = cast(int, s.getsockname()[1])  # closed again after the with block
    r = check_url(make(f"http://127.0.0.1:{port}/", timeout="2"))
    assert r.response_code == 0 and "ConnectionRefusedError" in r.error


def test_unresolvable_host() -> None:
    r = check_url(make("http://does-not-exist.invalid/", timeout="5"))
    assert r.response_code == 0 and r.error  # .invalid never resolves


def test_event_fields_omit_empty_error() -> None:
    s = make("https://example.com")
    assert "error" not in event_fields(s, CheckResult(200, 0.1))
    assert event_fields(s, CheckResult(0, 0.1, error="boom"))["error"] == "boom"
