import errno
import socket
import threading
import time
import urllib.error
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import ping_check
import pytest
from compat import override
from ping_check import check_url
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
        elif self.path == "/slow-body":
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.flush()
            time.sleep(3)
            _ = self.wfile.write(b"late")
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
    before = time.time()
    r = check_url(make(base_url + "/ok"))
    assert (r.response_code, r.timed_out, r.error) == (200, False, "")
    assert not r.exceeded_redirects
    assert 0 < r.elapsed < 5
    assert before <= r.finished <= time.time()


def test_404_is_a_result_not_an_error(base_url: str) -> None:
    r = check_url(make(base_url + "/missing"))
    assert (r.response_code, r.error) == (404, "")


def test_redirects_are_followed(base_url: str) -> None:
    assert (
        check_url(make(base_url + "/redir/3", max_redirects="5")).response_code == 200
    )


def test_redirect_limit_means_no_response(base_url: str) -> None:
    r = check_url(make(base_url + "/redir/5", max_redirects="2"))
    assert r.response_code is None and r.exceeded_redirects and not r.timed_out
    assert r.error == "redirect limit of 2 reached"


def test_zero_redirects_stops_at_the_first_redirect(base_url: str) -> None:
    r = check_url(make(base_url + "/redir/1", max_redirects="0"))
    assert r.response_code is None and r.exceeded_redirects
    assert r.error == "redirect limit of 0 reached"


def test_timeout(base_url: str) -> None:
    r = check_url(make(base_url + "/hang", timeout="1"))
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2.5


def test_body_too_slow_is_a_timeout(base_url: str) -> None:
    r = check_url(make(base_url + "/slow-body", timeout="1"))
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2.5


def test_connection_refused() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = cast(int, s.getsockname()[1])  # closed again after the with block
    r = check_url(make(f"http://127.0.0.1:{port}/", timeout="2"))
    assert r.response_code is None and not r.timed_out
    assert "ConnectionRefusedError" in r.error


def test_unresolvable_host() -> None:
    r = check_url(make("http://does-not-exist.invalid/", timeout="5"))
    assert r.response_code is None and r.error  # .invalid never resolves


def _raise(exc: BaseException) -> Callable[..., tuple[int, bool]]:
    def fetch(*_args: object) -> tuple[int, bool]:
        raise exc

    return fetch


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ETIMEDOUT, "Connection timed out"),
        urllib.error.URLError(OSError(errno.ETIMEDOUT, "Connection timed out")),
        urllib.error.URLError(socket.timeout("timed out")),
        TimeoutError(),
    ],
    ids=["oserror", "urlerror-oserror", "urlerror-timeout", "timeouterror"],
)
def test_kernel_connect_timeout_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    monkeypatch.setattr(ping_check, "_fetch", _raise(exc))
    r = check_url(make("http://example.invalid/"))
    assert r.timed_out and r.response_code is None and r.error == ""


def test_unexpected_exception_still_gives_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ping_check, "_fetch", _raise(KeyError("x")))
    r = check_url(make("http://example.invalid/"))
    assert r.response_code is None and not r.timed_out
    assert r.error == "unexpected KeyError: 'x'"
