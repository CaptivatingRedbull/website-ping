"""The test target's routes, served on a loopback port. mTLS and Squid are probed in Docker."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
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
