"""The test target's routes, served on a loopback port. mTLS and Squid are probed in Docker."""

from __future__ import annotations

import base64
import gzip
import http.cookiejar
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Iterator
from email.message import Message

import pytest
from target import server

USER, PASSWORD = server.AUTH_USER, server.AUTH_PASSWORD


@pytest.fixture(scope="module")
def base() -> Iterator[str]:
    httpd = server.Server(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def logged(capsys: pytest.CaptureFixture[str]) -> list[dict[str, object]]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]


def no_proxy_opener(
    *handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), *handlers)


def get(url: str, headers: dict[str, str] | None = None) -> tuple[int, Message, bytes]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with no_proxy_opener().open(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.mark.parametrize(
    ("case", "content_type", "encoding"),
    [
        ("utf8-charset", "text/html; charset=utf-8", "utf-8"),
        ("latin1-charset", "text/html; charset=iso-8859-1", "latin-1"),
        ("text-no-charset", "text/html", "latin-1"),
        ("json-no-charset", "application/json", "utf-8"),
    ],
)
def test_content_text(base: str, case: str, content_type: str, encoding: str) -> None:
    status, headers, body = get(f"{base}/content/{case}/t")
    assert status == 200
    assert headers["Content-Type"] == content_type
    assert b"WPTEST-MARKER" in body
    assert "Grüße".encode(encoding) in body


def test_content_bodies_are_fixed(base: str) -> None:
    assert (
        get(f"{base}/content/utf8-charset/a")[2]
        == get(f"{base}/content/utf8-charset/b")[2]
    )
    assert (
        get(f"{base}/content/latin1-charset/t")[2]
        != get(f"{base}/content/utf8-charset/t")[2]
    )


def test_content_binary(base: str) -> None:
    status, headers, body = get(f"{base}/content/binary/t")
    assert (status, headers["Content-Type"], body) == (
        200,
        "application/octet-stream",
        bytes(range(256)),
    )


def test_content_unknown_case(base: str) -> None:
    assert get(f"{base}/content/nope/t")[0] == 404


@pytest.mark.parametrize("size", [0, 1, 10, 12345, server.BIG_LIMIT])
def test_big(base: str, size: int) -> None:
    status, headers, body = get(f"{base}/big/{size}/t")
    assert status == 200
    assert headers["Content-Type"] == "text/plain; charset=utf-8"
    assert len(body) == size
    assert body == (b"0123456789" * (size // 10 + 1))[:size]


def test_big_over_limit(base: str) -> None:
    assert get(f"{base}/big/{server.BIG_LIMIT + 1}/t")[0] == 400


def test_headers(base: str) -> None:
    status, headers, body = get(f"{base}/headers/t")
    assert (status, body) == (200, b"ok")
    assert headers["X-Wptest"] == "one"
    assert headers["X-Wptest-Space"] == 'a b "c"'
    assert headers.get_all("Set-Cookie") == ["a=1", "b=2"]


def test_slow(base: str) -> None:
    started = time.monotonic()
    status, _, body = get(f"{base}/slow/300/t")
    assert (status, body) == (200, b"ok")
    assert time.monotonic() - started >= 0.3


def test_slow_over_limit(base: str) -> None:
    assert get(f"{base}/slow/{server.SLOW_LIMIT_MS + 1}/t")[0] == 400


def test_basic_success(base: str) -> None:
    assert get(f"{base}/auth/basic/t", basic(USER, PASSWORD))[::2] == (
        200,
        b"authenticated",
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        basic(USER, "wrong"),
        basic("other", PASSWORD),
        {"Authorization": "Basic !!!"},
        {"Authorization": "Bearer abc"},
    ],
)
def test_basic_failure(base: str, headers: dict[str, str]) -> None:
    status, response_headers, _ = get(f"{base}/auth/basic/t", headers)
    assert status == 401
    assert response_headers.get_all("WWW-Authenticate") == ['Basic realm="wptest"']


def test_digest_success(base: str, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, base, USER, PASSWORD)
    opener = no_proxy_opener(urllib.request.HTTPDigestAuthHandler(manager))
    with opener.open(f"{base}/auth/digest/t?x=1", timeout=10) as response:
        assert (response.status, response.read()) == (200, b"authenticated")
    lines = [r for r in logged(capsys) if r.get("path") == "/auth/digest/t?x=1"]
    assert [(r["status"], r["authorization"]) for r in lines] == [
        (401, ""),
        (200, "Digest"),
    ]


def test_digest_wrong_password(base: str) -> None:
    manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, base, USER, "wrong")
    opener = no_proxy_opener(urllib.request.HTTPDigestAuthHandler(manager))
    with pytest.raises(urllib.error.HTTPError) as caught:
        opener.open(f"{base}/auth/digest/t", timeout=10)
    assert caught.value.code == 401


def test_digest_challenge(base: str) -> None:
    status, headers, _ = get(f"{base}/auth/digest/t")
    assert status == 401
    challenges = headers.get_all("WWW-Authenticate") or []
    assert len(challenges) == 1
    assert challenges[0].startswith('Digest realm="wptest", qop="auth", algorithm=MD5')
    nonces = {
        get(f"{base}/auth/digest/t")[1]["WWW-Authenticate"].split('nonce="')[1][:32]
        for _ in range(2)
    }
    assert len(nonces) == 2, "a fresh nonce per 401"


def test_digest_unknown_nonce(base: str) -> None:
    header = (
        f'Digest username="{USER}", realm="wptest", nonce="{"0" * 32}", '
        'uri="/auth/digest/t", response="00", qop=auth, nc=00000001, cnonce="x"'
    )
    assert get(f"{base}/auth/digest/t", {"Authorization": header})[0] == 401


def test_ntlm(base: str) -> None:
    status, headers, _ = get(f"{base}/auth/ntlm/t", basic(USER, PASSWORD))
    assert status == 401
    assert headers.get_all("WWW-Authenticate") == ["NTLM", "Negotiate"]


def test_unknown_auth_scheme(base: str) -> None:
    assert get(f"{base}/auth/bearer/t")[0] == 404


def test_log_has_scheme_method_and_no_credentials(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    get(f"{base}/auth/basic/t", basic(USER, PASSWORD))
    get(f"{base}/status/200", {"User-Agent": "wptest-ua"})
    output = capsys.readouterr().out
    assert PASSWORD not in output
    assert base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode() not in output
    lines = [json.loads(line) for line in output.splitlines() if line]
    assert [
        (r["method"], r["path"], r["authorization"], r["status"]) for r in lines
    ] == [
        ("GET", "/auth/basic/t", "Basic", 200),
        ("GET", "/status/200", "", 200),
    ]
    assert lines[1]["user_agent"] == "wptest-ua"
    assert all("client_cn" not in r for r in lines)


def test_existing_routes_unchanged(base: str) -> None:
    assert get(f"{base}/status/503")[0] == 503
    assert get(f"{base}/done/t")[::2] == (200, b"ok")
    assert get(f"{base}/no-such-route")[0] == 404


def raw_request(base: str, request: bytes) -> bytes:
    """Send request bytes as they are (the request should say Connection: close)
    and return the whole response."""
    host, port = base.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=10) as connection:
        connection.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def status_of(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def test_log_records_request_headers_in_order(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    response = raw_request(
        base,
        b"GET /status/200 HTTP/1.1\r\n"
        b"Host: h.test:8080\r\n"
        b"User-Agent: wptest-ua\r\n"
        b"Accept-Encoding: gzip, deflate\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n"
        b"Cookie: a=secret-1; b=secret-2\r\n"
        b"\r\n",
    )
    assert status_of(response) == 200
    output = capsys.readouterr().out
    assert "secret-" not in output
    (record,) = [json.loads(line) for line in output.splitlines() if line]
    assert record["header_names"] == [
        "Host",
        "User-Agent",
        "Accept-Encoding",
        "Accept",
        "Connection",
        "Cookie",
    ]
    assert (
        record["host"],
        record["accept"],
        record["accept_encoding"],
        record["connection"],
        record["cookie"],
    ) == ("h.test:8080", "*/*", "gzip, deflate", "close", "a,b")
    assert "request_line" not in record


def test_every_record_has_the_keys_of_an_empty_request(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    get(f"{base}/status/200")
    (record,) = logged(capsys)
    assert set(record) == {*server.EMPTY_REQUEST, "port", "time"}


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("gzip, deflate", True),
        ("deflate, GZIP;q=0.5", True),
        ("identity", False),
        ("", False),
        ("x-gzip", False),
    ],
)
def test_accepts_gzip(header: str, expected: bool) -> None:
    assert server.accepts_gzip(header) is expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [("", ""), ("a=1", "a"), ("a=1; b=2", "a,b"), (" a=1 ;; b", "a,b")],
)
def test_cookie_names(header: str, expected: str) -> None:
    assert server.cookie_names(header) == expected


def test_gzip_only_when_accepted(base: str) -> None:
    _, headers, body = get(f"{base}/gzip/t", {"Accept-Encoding": "gzip, deflate"})
    assert headers["Content-Encoding"] == "gzip"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert gzip.decompress(body) == server.ENCODED_BODY
    _, headers, body = get(f"{base}/gzip/t", {"Accept-Encoding": "identity"})
    assert "Content-Encoding" not in headers
    assert body == server.ENCODED_BODY


def test_gzip_forced(base: str) -> None:
    first = get(f"{base}/gzip-forced/t", {"Accept-Encoding": "identity"})
    second = get(f"{base}/gzip-forced/u", {"Accept-Encoding": "identity"})
    assert first[1]["Content-Encoding"] == "gzip"
    assert gzip.decompress(first[2]) == server.ENCODED_BODY
    assert first[2] == second[2], "fixed gzip header time"


def test_deflate_is_zlib_wrapped(base: str) -> None:
    _, headers, body = get(f"{base}/deflate/t")
    assert headers["Content-Encoding"] == "deflate"
    assert zlib.decompress(body) == server.ENCODED_BODY


def test_deflate_raw(base: str) -> None:
    _, headers, body = get(f"{base}/deflate-raw/t")
    assert headers["Content-Encoding"] == "deflate"
    assert zlib.decompress(body, -zlib.MAX_WBITS) == server.ENCODED_BODY
    with pytest.raises(zlib.error):
        zlib.decompress(body)


def test_cookie_redirect_without_cookie(base: str) -> None:
    status, headers, _ = get(f"{base}/cookie/t")
    assert status == 302
    assert headers["Location"] == "/cookie/t"
    assert headers["Set-Cookie"] == "wptest_session=ok; Path=/"


def test_cookie_redirect_with_a_cookie_jar(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    opener = no_proxy_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    with opener.open(f"{base}/cookie/jar", timeout=10) as response:
        assert (response.status, response.read()) == (200, b"cookie ok")
    lines = [r for r in logged(capsys) if r["path"] == "/cookie/jar"]
    assert [(r["status"], r["cookie"]) for r in lines] == [
        (302, ""),
        (200, "wptest_session"),
    ]


def test_cookie_redirect_never_ends_without_cookies(base: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as caught:
        no_proxy_opener().open(f"{base}/cookie/none", timeout=10)
    assert caught.value.code == 302


def test_path_logs_the_request_line_bytes(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    line = b"GET /path/t/M\xc3\xbcller?q=M%C3%BCnchen HTTP/1.1"
    response = raw_request(base, line + b"\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert status_of(response) == 200
    (record,) = logged(capsys)
    assert record["status"] == 200
    assert str(record["request_line"]).encode("latin-1") == line


def test_path_with_a_raw_space_is_rejected_and_logged(
    base: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capsys.readouterr()
    line = b"GET /path/path-space/a b HTTP/1.1"
    response = raw_request(base, line + b"\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert status_of(response) == 400
    (record,) = logged(capsys)
    assert (record["method"], record["path"], record["status"]) == (
        "GET",
        "/path/path-space/a b",
        400,
    )
    assert record["rejected"] is True
    assert record["request_line"] == line.decode("latin-1")
    assert set(server.EMPTY_REQUEST) <= set(record)


def test_body_lines(base: str) -> None:
    status, headers, body = get(f"{base}/body-lines/t")
    assert (status, headers["Content-Type"]) == (200, "text/plain; charset=utf-8")
    lines = body.decode("ascii").splitlines()
    assert len(lines) == 5
    assert re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", lines[2])
    assert not any(
        re.search(r"\d{4}-\d\d", line) for i, line in enumerate(lines) if i != 2
    )


def test_body_binary(base: str) -> None:
    status, _, body = get(f"{base}/body-binary/t")
    assert status == 200
    assert {b"\x00", b"\x0b", b"\x1f"} <= {bytes([c]) for c in body}
    with pytest.raises(UnicodeDecodeError):
        body.decode("utf-8")
