from __future__ import annotations

import dataclasses
import errno
import gzip
import json
import socket
import ssl
import threading
import time
import urllib.error
from collections.abc import Callable, Iterator
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import NoReturn, cast

import ping_check
import pytest
from compat import override
from ping_check import check_url, response_content
from ping_config import DEFAULT_USER_AGENT, build_settings
from ping_events import escape_value
from target import server
from wp_content import MAX_BODY_BYTES
from wp_context import CheckContext, make_context
from wp_deadline import Phases
from wptest import golden, legacy, parity


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
        elif self.path.startswith("/gzip/"):
            body = gzip.compress(b"compressed body")
            kind = self.path.rsplit("/", 1)[1]
            if kind == "truncated":
                body = body[:-12]
            elif kind == "corrupt":
                body = b"\x1f\x8b\x08\x00" + b"x" * 20
            elif kind == "huge":
                body = gzip.compress(bytes(MAX_BODY_BYTES + 1024), compresslevel=1)
            self.send_response(200 if kind != "missing" else 404)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            _ = self.wfile.write(body)
        elif self.path == "/to-eszett":
            self.send_response(302)
            self.send_header("Location", "http://stra\xc3\x9fe.test/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/hang":
            time.sleep(3)
            self._send(200, b"late")
        elif self.path.startswith("/slow-redir/"):
            hops = int(self.path.rsplit("/", 1)[1])
            time.sleep(0.6)
            self.send_response(302)
            self.send_header("Location", f"/slow-redir/{hops + 1}")
            self.send_header("Content-Length", "0")
            self.end_headers()
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


def make(url: str, **extra: str) -> CheckContext:
    settings, _ = build_settings(
        "web_ping://test", {"url": url, "interval": "60", **extra}
    )
    return make_context(settings)


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


def test_redirect_to_refused_host_is_an_error(base_url: str) -> None:
    r = check_url(make(base_url + "/to-eszett"))
    assert (r.response_code, r.timed_out) == (None, False)
    assert r.error.startswith("HostNameError: host name 'straße.test'")


@pytest.mark.parametrize(
    ("kind", "code"), [("ok", 200), ("missing", 404), ("huge", 200)]
)
def test_compressed_body_is_read(base_url: str, kind: str, code: int) -> None:
    r = check_url(make(f"{base_url}/gzip/{kind}"))
    assert (r.response_code, r.timed_out, r.error) == (code, False, "")
    expected = MAX_BODY_BYTES if kind == "huge" else len("compressed body")
    assert r.content_size == expected  # hashes cover the first 50 MiB only


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("truncated", "the body ends before its gzip stream does"),
        ("corrupt", "cannot decode the gzip body"),
    ],
)
def test_body_that_does_not_decode_is_no_response(
    base_url: str, kind: str, message: str
) -> None:
    r = check_url(make(f"{base_url}/gzip/{kind}"))
    assert (r.response_code, r.timed_out) == (None, False)
    assert r.error.startswith(f"ContentDecodingError: {message}")


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


def _raise(exc: BaseException) -> Callable[..., NoReturn]:
    def fetch(*_args: object) -> NoReturn:
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


def test_expired_deadline_ends_the_body_read(base_url: str) -> None:
    phases = Phases()
    phases.stop()
    r = check_url(make(base_url + "/ok"), phases)
    assert r.timed_out and r.response_code is None


def test_timeout_covers_every_redirect_hop(base_url: str) -> None:
    r = check_url(make(base_url + "/slow-redir/0", timeout="2"))
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2.5


class TrickleServer:
    """Loopback server that sends its answer one byte every interval seconds:
    the body ("body") or the whole response from the status line on ("headers")."""

    def __init__(
        self, trickle: str, interval: float, tls: tuple[Path, Path] | None = None
    ) -> None:
        self.trickle: str = trickle
        self.interval: float = interval
        self.context: ssl.SSLContext | None = None
        if tls is not None:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(str(tls[0]), str(tls[1]))
        self.listener: socket.socket = socket.create_server(("127.0.0.1", 0))
        self.stop: threading.Event = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self) -> str:
        scheme = "https" if self.context else "http"
        return f"{scheme}://127.0.0.1:{self.listener.getsockname()[1]}/"

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
            head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
            if self.trickle == "body":
                conn.sendall(head)
                payload = b"x" * 1000
            else:
                payload = head + b"x" * 1000
            for byte in payload:
                if self.stop.wait(self.interval):
                    return
                conn.sendall(bytes([byte]))
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()


def test_trickled_body_ends_at_the_timeout() -> None:
    server = TrickleServer("body", 0.5)
    try:
        r = check_url(make(server.url, timeout="2"))
    finally:
        server.close()
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2.5


@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
@pytest.mark.parametrize("trickle", ["headers", "body"])
def test_expiry_ends_a_trickle(
    tls_files: tuple[Path, Path], tls: bool, trickle: str
) -> None:
    # Each byte arrives well within the socket timeout, so only the expiry (the
    # runner's tick in production, a timer here) can end the check.
    server = TrickleServer(trickle, 0.1, tls_files if tls else None)
    phases = Phases()
    timer = threading.Timer(1.0, phases.stop)
    timer.start()
    try:
        r = check_url(make(server.url, timeout="30"), phases)
    finally:
        timer.join()
        server.close()
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2


# ---- redirects, compared with Website Monitoring 2.9.7's fixtures -----------

GOLDEN_DIR = Path(__file__).parent / "golden" / legacy.LEGACY_VERSION
REDIRECT_FIXTURES = (
    "redirects-off",
    "over-3",
    "chain-at-3",
    "blank-25",
    "blank-31",
    "minus-one-25",
    "loop",
)


@pytest.fixture(scope="module")
def target_base() -> Iterator[str]:
    httpd = server.Server(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def target_requests(
    capsys: pytest.CaptureFixture[str], scenario: parity.ParityScenario
) -> list[dict[str, object]]:
    records = [
        cast("dict[str, object]", json.loads(line))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{")
    ]
    return [
        r
        for r in records
        if "path" in r and scenario.matches_request(0, str(r["path"]))
    ]


@pytest.mark.parametrize("title", REDIRECT_FIXTURES)
def test_redirects_match_the_fixture(
    target_base: str, capsys: pytest.CaptureFixture[str], title: str
) -> None:
    scenario = parity.by_title()[title]
    capture = golden.read_capture(GOLDEN_DIR, title)
    (event,) = [e for e in capture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    url = scenario.url.replace(parity.T, target_base)
    _ = capsys.readouterr()
    r = check_url(make(url, **scenario.settings))
    assert len(target_requests(capsys, scenario)) == len(capture.requests)
    code = event.fields["response_code"]
    assert r.response_code == (int(str(code)) if code else None)
    assert r.exceeded_redirects == ("exceeded_redirects" in event.fields)
    assert not r.timed_out


@pytest.mark.parametrize(
    ("path", "limit", "code", "requests"),
    [
        ("/chain/chain-at-50/50", "50", 200, 51),
        ("/chain/over-50/51", "50", None, 51),
        ("/repeat/repeat-8/8", "10", 200, 9),
        ("/loop/loop-10", "10", None, 11),
    ],
    ids=["chain-at-50", "over-50", "repeat-8", "loop-10"],
)
def test_only_max_redirects_limits_redirects(
    target_base: str,
    capsys: pytest.CaptureFixture[str],
    path: str,
    limit: str,
    code: int | None,
    requests: int,
) -> None:
    scenario = parity.ParityScenario(path.split("/")[2], parity.T + path)
    _ = capsys.readouterr()
    r = check_url(make(target_base + path, max_redirects=limit))
    assert len(target_requests(capsys, scenario)) == requests
    assert r.response_code == code
    assert r.exceeded_redirects == (code is None)
    if code is None:
        assert r.error == f"redirect limit of {limit} reached"


@pytest.mark.parametrize("title", ["path-unicode", "path-space"])
def test_request_line_matches_the_fixture(
    target_base: str, capsys: pytest.CaptureFixture[str], title: str
) -> None:
    scenario = parity.by_title()[title]
    capture = golden.read_capture(GOLDEN_DIR, title)
    url = scenario.url.replace(parity.T, target_base)
    _ = capsys.readouterr()
    r = check_url(make(url, **scenario.settings))
    assert r.response_code == 200
    logged = [
        str(record["request_line"]) for record in target_requests(capsys, scenario)
    ]
    assert logged == [request.request_line for request in capture.requests]


# ---- request headers and cookies, compared with the fixtures ------------------


def comparable(request: golden.TargetRequest) -> golden.TargetRequest:
    """Without what differs by test setup (the target's address) or by design
    (Connection: one connection per request; the default user agent)."""
    return dataclasses.replace(request, port=0, host="", connection="", user_agent="")


@pytest.mark.parametrize(
    "title", ["request-headers", "redirect-302", "cookie-redirect"]
)
def test_request_headers_match_the_fixture(
    target_base: str, capsys: pytest.CaptureFixture[str], title: str
) -> None:
    scenario = parity.by_title()[title]
    capture = golden.read_capture(GOLDEN_DIR, title)
    url = scenario.url.replace(parity.T, target_base)
    _ = capsys.readouterr()
    r = check_url(make(url, **scenario.settings))
    assert r.response_code == 200
    sent = [
        golden.target_request(record) for record in target_requests(capsys, scenario)
    ]
    assert [comparable(s) for s in sent] == [comparable(e) for e in capture.requests]
    assert {(s.connection, s.user_agent) for s in sent} == {
        ("close", DEFAULT_USER_AGENT)
    }


def test_cookie_jar_is_new_for_every_check(
    target_base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    scenario = parity.by_title()["cookie-redirect"]
    url = scenario.url.replace(parity.T, target_base)
    _ = capsys.readouterr()
    for _check in range(2):
        assert check_url(make(url)).response_code == 200
    cookies = [str(record["cookie"]) for record in target_requests(capsys, scenario)]
    assert cookies == ["", "wptest_session", "", "wptest_session"]


@pytest.mark.parametrize("title", ["gzip", "gzip-forced", "deflate", "deflate-raw"])
def test_encoded_routes_are_decoded(
    target_base: str, capsys: pytest.CaptureFixture[str], title: str
) -> None:
    scenario = parity.by_title()[title]
    url = scenario.url.replace(parity.T, target_base)
    _ = capsys.readouterr()
    r = check_url(make(url, **scenario.settings))
    assert (r.response_code, r.error) == (200, "")
    (sent,) = target_requests(capsys, scenario)
    assert sent["accept_encoding"] == "gzip, deflate"


# ---- content, compared with the fixtures ---------------------------------------

CONTENT_FIELDS = (
    "content_md5",
    "content_sha224",
    "content_size",
    "has_expected_string",
)


def check_fields(title: str) -> dict[str, golden.FieldValue]:
    capture = golden.read_capture(GOLDEN_DIR, title)
    checks = [e for e in capture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    return dict(checks[-1].fields)


def _content_titles() -> list[str]:
    """Scenarios on the plain target whose fixture has content fields, without
    authentication (stored passwords are not read in unit tests) and without an
    allowed difference on every field."""
    return [
        s.title
        for s in parity.PARITY_SCENARIOS
        if s.url.startswith(parity.T)
        and "username" not in s.settings
        and golden.ANY_FIELD not in golden.allowed_fields(s.title)
        and "content_md5" in check_fields(s.title)
    ]


def content_of(r: ping_check.CheckResult) -> dict[str, str | None]:
    """The content fields of a result as the event writes them."""
    size, found = r.content_size, r.has_expected_string
    return {
        "content_md5": r.content_md5,
        "content_sha224": r.content_sha224,
        "content_size": None if size is None else str(size),
        "has_expected_string": None if found is None else str(found).lower(),
    }


@pytest.mark.parametrize("title", _content_titles())
def test_content_fields_match_the_fixture(target_base: str, title: str) -> None:
    scenario = parity.by_title()[title]
    expected = check_fields(title)
    allowed = golden.allowed_fields(title)
    r = check_url(
        make(scenario.url.replace(parity.T, target_base), **scenario.settings)
    )
    got = content_of(r)
    for name in CONTENT_FIELDS:
        if name not in allowed:
            assert got[name] == expected.get(name), name


def test_content_scenarios_are_all_checked() -> None:
    titles = set(_content_titles())
    assert {f"content-{case}" for case in server.CONTENT_CASES} <= titles
    assert {"match-yes", "match-no", "gzip", "deflate-raw", "status-404"} <= titles


def test_headers_match_the_fixture(target_base: str) -> None:
    scenario = parity.by_title()["headers"]
    capture = golden.read_capture(GOLDEN_DIR, "headers")
    (event,) = [e for e in capture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    expected = [p for p in golden.parse_raw(event.raw) if p.key.startswith("header_")]
    r = check_url(
        make(scenario.url.replace(parity.T, target_base), **scenario.settings)
    )
    assert r.headers is not None
    got = [
        golden.RawPair(f"header_{name}", escape_value(value))
        for name, value in r.headers
    ]
    normalised = [
        golden.RawPair(p.key, golden.normalise_literal(p.key, p.literal)) for p in got
    ]
    assert normalised == expected


@pytest.mark.parametrize(
    "title", ["body-big", "body-small", "body-lines", "body-binary"]
)
def test_body_matches_the_fixture(target_base: str, title: str) -> None:
    """The body event's text before Splunk: Splunk drops the line break at the
    end of an event, and dropped the NUL that 2.9.7 wrote into its stream."""
    scenario = parity.by_title()[title]
    capture = golden.read_capture(GOLDEN_DIR, title)
    (event,) = [e for e in capture.events if e.sourcetype == golden.RESPONSE_SOURCETYPE]
    r = check_url(
        make(scenario.url.replace(parity.T, target_base), **scenario.settings)
    )
    assert r.body is not None
    assert r.body.replace("\x00", "").rstrip("\n") == event.raw


def test_no_content_without_a_response(base_url: str) -> None:
    for url in (base_url + "/hang", base_url + "/redir/3"):
        r = check_url(
            make(
                url,
                timeout="1",
                max_redirects="1",
                should_contain_string="x",
                return_body="1",
                return_headers="1",
            )
        )
        assert r.response_code is None
        assert set(content_of(r).values()) == {None}
        assert (r.headers, r.body) == (None, None)


def test_content_of_an_error_status(base_url: str) -> None:
    r = check_url(
        make(
            base_url + "/missing",
            should_contain_string="nope",
            return_body="1",
            return_headers="1",
        )
    )
    assert (r.response_code, r.has_expected_string, r.body) == (404, True, "nope")
    assert r.content_size == 4
    assert r.headers is not None and ("Content-Length", "4") in r.headers


def plain_headers() -> Message:
    headers = Message()
    headers["Content-Type"] = "text/plain"
    headers["X-One"] = "1"
    return headers


@pytest.mark.parametrize(
    ("extra", "limit", "found", "headers", "body"),
    [
        ({}, 1000, None, None, None),
        ({"should_contain_string": "llo w"}, 1000, True, None, None),
        ({"should_contain_string": "HELLO"}, 1000, False, None, None),
        (
            {"return_headers": "1"},
            1000,
            None,
            (("Content-Type", "text/plain"), ("X-One", "1")),
            None,
        ),
        ({"return_body": "1"}, 1000, None, None, "hello world"),
        ({"return_body": "1"}, 5, None, None, "hello"),
        ({"return_body": "1"}, -1, None, None, "hello world"),
        ({"return_body": "1"}, 0, None, None, None),
        ({"return_body": "0"}, -1, None, None, None),
    ],
)
def test_response_content_takes_what_the_stanza_asks_for(
    extra: dict[str, str],
    limit: int,
    found: bool | None,
    headers: tuple[tuple[str, str], ...] | None,
    body: str | None,
) -> None:
    settings, _ = build_settings(
        "web_ping://test", {"url": "http://x/", "interval": "60", **extra}
    )
    content = response_content(settings, limit, plain_headers(), b"hello world")
    assert content.hashes.size == len("hello world")
    assert (content.has_expected_string, content.headers, content.body) == (
        found,
        headers,
        body,
    )
