"""HTTP authentication of a check: scheme detection, Basic, Digest, NTLM and
Negotiate, against the test target's auth routes and small local servers."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
import urllib.request
from collections.abc import Iterator, Sequence
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, NoReturn, cast
from urllib.request import parse_http_list, parse_keqv_list

import ping_check
import pytest
import wp_auth
from compat import override
from logger import StanzaLogger, log_to_stderr, setup_logging
from ping_check import CheckResult, check_url
from ping_config import build_settings
from target import server
from wp_auth import (
    BASIC,
    DIGEST,
    NONE,
    AuthorizationHandler,
    Credentials,
    DigestChallenge,
    DigestError,
    WarnOnce,
    answer_for,
    basic_authorization,
    credentials,
    detect_scheme,
    digest_authorization,
    digest_challenge,
    request_uri,
    scheme_of,
)
from wp_context import CheckContext, make_context
from wptest import golden, legacy

USER, PASSWORD = server.AUTH_USER, server.AUTH_PASSWORD
GOLDEN_DIR = Path(__file__).parent / "golden" / legacy.LEGACY_VERSION
BASIC_TOKEN = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


@pytest.fixture(autouse=True)
def fresh_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wp_auth, "WARNED", WarnOnce())


@pytest.fixture
def log_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) is not None
    yield path
    log_to_stderr()


@pytest.fixture(scope="module")
def target() -> Iterator[str]:
    httpd = server.Server(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def make(url: str, password: str | None = None, **extra: str) -> CheckContext:
    settings, _ = build_settings(
        "web_ping://auth", {"url": url, "interval": "60", "log_level": "DEBUG", **extra}
    )
    return make_context(settings, password=password)


def requests_to(
    capsys: pytest.CaptureFixture[str], path: str
) -> list[dict[str, object]]:
    """The target's log records of requests to path since the last call."""
    records = [
        cast("dict[str, object]", json.loads(line))
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{")
    ]
    return [r for r in records if r.get("path") == path]


def sent(records: Sequence[dict[str, object]]) -> list[tuple[object, object]]:
    return [(r["authorization"], r["status"]) for r in records]


# ---- scheme detection -------------------------------------------------------


@pytest.mark.parametrize(
    ("offered", "scheme"),
    [
        ([], "basic"),
        (['Basic realm="wptest"'], "basic"),
        (['Digest realm="wptest", qop="auth"'], "digest"),
        (["NTLM", "Negotiate"], "ntlm"),
        (["Negotiate, NTLM"], "ntlm"),
        (["Negotiate", 'Basic realm="x"'], "negotiate"),
        (['Bearer realm="api"'], "bearer"),
        (["  Basic"], "basic"),
        (['"quoted"'], "basic"),
        ([""], "basic"),
    ],
)
def test_scheme_of(offered: list[str], scheme: str) -> None:
    assert scheme_of(offered) == scheme


def headers(*challenges: str) -> Message:
    message = Message()
    for challenge in challenges:
        message["WWW-Authenticate"] = challenge
    return message


def test_detect_scheme_reads_every_header(log_file: Path) -> None:
    log = StanzaLogger("web_ping://auth", logging.DEBUG)
    assert detect_scheme(lambda: headers("Negotiate", "NTLM"), log) == "ntlm"
    assert detect_scheme(lambda: headers(), log) == BASIC
    text = log_file.read_text(encoding="utf-8")
    assert "site offers authentication scheme ntlm" in text
    assert "site sent no WWW-Authenticate header, using basic" in text


def test_failed_probe_means_basic_with_a_warning(log_file: Path) -> None:
    def fail() -> NoReturn:
        raise ConnectionResetError("reset by peer")

    assert detect_scheme(fail, StanzaLogger("web_ping://auth")) == BASIC
    line = log_file.read_text(encoding="utf-8").splitlines()[0]
    assert " WARN stanza=web_ping://auth " in line
    assert line.endswith(
        "could not ask the site for its authentication scheme, using basic:"
        " ConnectionResetError: reset by peer"
    )


def test_answer_for_warns_once_per_stanza_and_scheme(log_file: Path) -> None:
    a, b = StanzaLogger("web_ping://a"), StanzaLogger("web_ping://b")
    assert answer_for("ntlm", "web_ping://a", a) == NONE
    assert answer_for("ntlm", "web_ping://a", a) == NONE
    assert answer_for("negotiate", "web_ping://a", a) == NONE
    assert answer_for("ntlm", "web_ping://b", b) == NONE
    assert answer_for("bearer", "web_ping://a", a) == BASIC
    assert answer_for("bearer", "web_ping://a", a) == BASIC
    assert answer_for("basic", "web_ping://a", a) == BASIC
    assert answer_for("digest", "web_ping://a", a) == DIGEST
    lines = log_file.read_text(encoding="utf-8").splitlines()
    without = "which is not supported; requests are sent without credentials"
    as_basic = (
        "which is not supported; sending basic credentials, as Website Monitoring did"
    )
    assert [line.split(" v=", 1)[1].split(" ", 1)[1] for line in lines] == [
        f"site offers NTLM authentication, {without}",
        f"site offers Negotiate authentication, {without}",
        f"site offers NTLM authentication, {without}",
        f"site offers bearer authentication, {as_basic}",
    ]


# ---- credentials and the Authorization header -------------------------------


def test_credentials_need_both_parts() -> None:
    assert credentials(None, "pw") is None
    assert credentials("u", None) is None
    creds = credentials("u", "pw")
    assert creds == Credentials("u", "pw") and "pw" not in repr(creds)


def test_basic_authorization_latin1_then_utf8() -> None:
    assert basic_authorization(Credentials(USER, PASSWORD)) == f"Basic {BASIC_TOKEN}"
    latin1 = base64.b64encode("jörg:pässword".encode("latin-1")).decode()
    assert basic_authorization(Credentials("jörg", "pässword")) == f"Basic {latin1}"
    utf8 = base64.b64encode("u:пароль".encode()).decode()
    assert basic_authorization(Credentials("u", "пароль")) == f"Basic {utf8}"


def test_authorization_only_to_the_checked_host() -> None:
    handler = AuthorizationHandler("http://site.test:8080/a", "Basic x")
    same = urllib.request.Request("https://site.test/redirected")
    other = urllib.request.Request("http://elsewhere.test/")
    assert handler.http_request(same).unredirected_hdrs == {"Authorization": "Basic x"}
    assert handler.http_request(other).unredirected_hdrs == {}
    assert "Authorization" not in same.headers  # a redirect does not copy it


# ---- checks against the target's auth routes --------------------------------


def golden_header_names(title: str) -> list[list[str]]:
    capture = golden.read_capture(GOLDEN_DIR, title)
    return [list(r.header_names) for r in capture.requests]


def test_basic_probe_then_credentials_up_front(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/auth/basic/basic-plain"
    _ = capsys.readouterr()
    r = check_url(make(target + path, PASSWORD, username=USER))
    assert r.response_code == 200 and r.error == ""
    records = requests_to(capsys, path)
    assert sent(records) == [("", 401), ("Basic", 200)]
    assert [r["header_names"] for r in records] == golden_header_names("basic-plain")


def test_wrong_password_gives_the_401(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/auth/basic/auth-wrong"
    _ = capsys.readouterr()
    r = check_url(make(target + path, "wptest-wrong-password", username=USER))
    assert r.response_code == 401 and not r.timed_out and r.error == ""
    assert sent(requests_to(capsys, path)) == [("", 401), ("Basic", 401)]
    expected = golden.read_capture(GOLDEN_DIR, "auth-wrong")
    assert len(expected.requests) == 2


def test_ntlm_sends_no_credentials_and_warns_once(
    target: str, capsys: pytest.CaptureFixture[str], log_file: Path
) -> None:
    path = "/auth/ntlm/ntlm-offered"
    _ = capsys.readouterr()
    results = [check_url(make(target + path, PASSWORD, username=USER)) for _ in "ab"]
    assert [r.response_code for r in results] == [401, 401]
    assert sent(requests_to(capsys, path)) == [("", 401)] * 4
    warnings = [
        line
        for line in log_file.read_text(encoding="utf-8").splitlines()
        if "NTLM authentication, which is not supported" in line
    ]
    assert len(warnings) == 1


def test_no_challenge_still_sends_basic(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/done/no-challenge"
    _ = capsys.readouterr()
    assert check_url(make(target + path, PASSWORD, username=USER)).response_code == 200
    assert sent(requests_to(capsys, path)) == [("", 200), ("Basic", 200)]


@pytest.mark.parametrize(
    ("password", "extra"),
    [(None, {"username": USER}), (PASSWORD, {})],
    ids=["username-only", "password-only"],
)
def test_without_both_parts_no_probe_and_no_credentials(
    target: str,
    capsys: pytest.CaptureFixture[str],
    password: str | None,
    extra: dict[str, str],
) -> None:
    path = "/auth/basic/half"
    _ = capsys.readouterr()
    assert check_url(make(target + path, password, **extra)).response_code == 401
    assert sent(requests_to(capsys, path)) == [("", 401)]


def test_failed_probe_falls_back_to_basic(
    target: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    log_file: Path,
) -> None:
    def fail(*_args: object) -> NoReturn:
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(ping_check, "_probe", fail)
    path = "/auth/basic/probe-failed"
    _ = capsys.readouterr()
    assert check_url(make(target + path, PASSWORD, username=USER)).response_code == 200
    assert sent(requests_to(capsys, path)) == [("Basic", 200)]
    assert "using basic: ConnectionRefusedError: refused" in log_file.read_text(
        encoding="utf-8"
    )


def test_credentials_are_never_logged(
    target: str, capsys: pytest.CaptureFixture[str], log_file: Path
) -> None:
    for path in ("/auth/basic/a", "/auth/ntlm/b", "/done/c"):
        _ = check_url(make(target + path, PASSWORD, username=USER))
    text = log_file.read_text(encoding="utf-8") + capsys.readouterr().out
    assert "auth" in text  # the check did log
    assert PASSWORD not in text and BASIC_TOKEN not in text


# ---- the probe's own time ---------------------------------------------------


class Scripted(BaseHTTPRequestHandler):
    """Answers request n after delays[n] seconds: first a Basic challenge, then
    200 for a request with the right credentials."""

    protocol_version = "HTTP/1.1"
    delays: ClassVar[list[float]] = []
    seen: ClassVar[list[str]] = []
    lock: ClassVar[threading.Lock] = threading.Lock()

    def do_GET(self) -> None:
        with self.lock:
            index = len(self.seen)
            self.seen.append(self.headers.get("Authorization", ""))
        time.sleep(self.delays[index] if index < len(self.delays) else 0)
        ok = self.headers.get("Authorization", "") == f"Basic {BASIC_TOKEN}"
        body = b"ok" if ok else b"no"
        self.send_response(200 if ok else 401)
        if not ok:
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        _ = self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


def scripted(delays: list[float]) -> tuple[str, ThreadingHTTPServer]:
    Scripted.delays, Scripted.seen = delays, []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Scripted)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{httpd.server_address[1]}/", httpd


def run(url: str, timeout: str) -> CheckResult:
    return check_url(make(url, PASSWORD, username=USER, timeout=timeout))


def test_probe_and_request_each_get_the_timeout() -> None:
    url, httpd = scripted([0.7, 0.7])
    try:
        r = run(url, "1")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert r.response_code == 200 and not r.timed_out
    assert 0.6 < r.elapsed < 1.0, "the probe is not part of the measured time"
    assert Scripted.seen == ["", f"Basic {BASIC_TOKEN}"]


def test_probe_timeout_falls_back_to_basic(log_file: Path) -> None:
    url, httpd = scripted([2.0, 0.0])
    try:
        r = run(url, "1")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert r.response_code == 200 and not r.timed_out
    assert r.elapsed < 0.5
    assert "could not ask the site for its authentication scheme, using basic" in (
        log_file.read_text(encoding="utf-8")
    )


# ---- Digest: parsing and the response ---------------------------------------


def test_digest_challenge_fields() -> None:
    challenge = digest_challenge(
        [
            'Basic realm="x"',
            (
                'Digest realm="r", nonce="n", qop="auth,auth-int", algorithm=SHA-256,'
                ' opaque="o", stale=false'
            ),
        ]
    )
    assert challenge == DigestChallenge("r", "n", "SHA-256", True, "o")
    assert digest_challenge(['DIGEST Realm="r", NONCE="n"']) == DigestChallenge(
        "r", "n", None, False, None
    )
    assert digest_challenge(['Basic realm="x"']) is None


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        ('Digest nonce="n"', "challenge without realm or nonce"),
        ('Digest realm="r"', "challenge without realm or nonce"),
        ('Digest realm="r", nonce="n", algorithm=SHA-512', "algorithm SHA-512"),
        ('Digest realm="r", nonce="n", algorithm=SHA-256-sess', "SHA-256-sess"),
        ('Digest realm="r", nonce="n", qop="auth-int"', "qop auth-int"),
        ('Digest realm="r", nonce="n", algorithm=MD5-sess', "MD5-sess without qop"),
    ],
)
def test_digest_challenge_not_answerable(header: str, reason: str) -> None:
    with pytest.raises(DigestError, match=reason):
        _ = digest_challenge([header])


def test_request_uri() -> None:
    assert request_uri("http://h/") == "/"
    assert request_uri("http://h") == "/"
    assert request_uri("http://h/a%20b?q=1&r=%C3%BC") == "/a%20b?q=1&r=%C3%BC"


def test_digest_rfc_2617_example() -> None:
    challenge = DigestChallenge(
        "testrealm@host.com",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        None,
        True,
        "5ccc069c403ebaf9f0171e9517f40e41",
    )
    value = digest_authorization(
        Credentials("Mufasa", "Circle Of Life"),
        challenge,
        "GET",
        "/dir/index.html",
        cnonce="0a4f113b",
    )
    assert value == (
        'Digest username="Mufasa", realm="testrealm@host.com",'
        ' nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html",'
        ' response="6629fae49393a05397450978507c4ef1",'
        ' opaque="5ccc069c403ebaf9f0171e9517f40e41",'
        ' qop="auth", nc=00000001, cnonce="0a4f113b"'
    )


@pytest.mark.parametrize(
    ("algorithm", "response"),
    [
        ("MD5", "8ca523f5e9506fed4657c9700eebdbec"),
        ("SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"),
    ],
)
def test_digest_rfc_7616_examples(algorithm: str, response: str) -> None:
    challenge = DigestChallenge(
        "http-auth@example.org",
        "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        algorithm,
        True,
        "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
    )
    value = digest_authorization(
        Credentials("Mufasa", "Circle of Life"),
        challenge,
        "GET",
        "/dir/index.html",
        cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
    )
    assert f'response="{response}"' in value
    assert f'algorithm="{algorithm}"' in value


def test_digest_quotes_and_never_contains_the_password() -> None:
    challenge = DigestChallenge("r", "n", None, False, None)
    value = digest_authorization(Credentials('a"b\\c', PASSWORD), challenge, "GET", "/")
    assert value.startswith('Digest username="a\\"b\\\\c", realm="r"')
    assert "qop" not in value and "algorithm" not in value and "opaque" not in value
    assert PASSWORD not in value


def test_digest_hashes_are_not_for_security(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    real = hashlib.new

    def recording(name: str, data: bytes = b"", **kwargs: Any) -> Any:
        calls.append({"name": name, **kwargs})
        return real(name, data, **kwargs)

    monkeypatch.setattr(hashlib, "new", recording)
    challenge = DigestChallenge("r", "n", "MD5-sess", True, None)
    _ = digest_authorization(Credentials("u", "p"), challenge, "GET", "/")
    assert calls and all(c == {"name": "md5", "usedforsecurity": False} for c in calls)


def test_digest_without_the_hash_on_this_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> NoReturn:
        raise ValueError("[digital envelope routines] unsupported")

    monkeypatch.setattr(hashlib, "new", refuse)
    challenge = DigestChallenge("r", "n", None, True, None)
    with pytest.raises(
        DigestError, match="algorithm MD5 is not available on this host"
    ):
        _ = digest_authorization(Credentials("u", "p"), challenge, "GET", "/")


# ---- Digest: checks against servers -----------------------------------------


def test_digest_against_the_target(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/auth/digest/digest-plain"
    _ = capsys.readouterr()
    r = check_url(make(target + path, PASSWORD, username=USER))
    assert r.response_code == 200 and r.error == ""
    records = requests_to(capsys, path)
    assert sent(records) == [("", 401), ("", 401), ("Digest", 200)]
    assert [r["header_names"] for r in records] == golden_header_names("digest-plain")


def test_digest_wrong_password_one_round_only(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "/auth/digest/digest-wrong"
    _ = capsys.readouterr()
    r = check_url(make(target + path, "wptest-wrong-password", username=USER))
    assert r.response_code == 401 and not r.timed_out
    assert sent(requests_to(capsys, path)) == [("", 401), ("", 401), ("Digest", 401)]


def _h(name: str, text: str) -> str:
    return hashlib.new(name, text.encode()).hexdigest()


class DigestServer(BaseHTTPRequestHandler):
    """Digest with the challenge in `challenge` ("{nonce}" is replaced). Checks a
    response the way RFC 7616 describes it, independently of wp_auth."""

    protocol_version = "HTTP/1.1"
    challenge: ClassVar[str] = ""
    nonce: ClassVar[str] = "4f1c2a"
    seen: ClassVar[list[str]] = []
    lock: ClassVar[threading.Lock] = threading.Lock()

    def do_GET(self) -> None:
        header = self.headers.get("Authorization", "")
        with self.lock:
            self.seen.append(header)
        ok = self._valid(header)
        body = b"ok" if ok else b"no"
        self.send_response(200 if ok else 401)
        if not ok:
            self.send_header(
                "WWW-Authenticate", self.challenge.replace("{nonce}", self.nonce)
            )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        _ = self.wfile.write(body)

    def _valid(self, header: str) -> bool:
        scheme, _, rest = header.partition(" ")
        if scheme != "Digest":
            return False
        f = parse_keqv_list(parse_http_list(rest))
        algorithm = f.get("algorithm", "MD5").upper()
        name = {"MD5": "md5", "MD5-SESS": "md5", "SHA": "sha1", "SHA-256": "sha256"}[
            algorithm
        ]
        ha1 = _h(name, f"{USER}:wptest:{PASSWORD}")
        if algorithm.endswith("-SESS"):
            ha1 = _h(name, f"{ha1}:{self.nonce}:{f['cnonce']}")
        ha2 = _h(name, f"GET:{self.path}")
        if "qop" in f:
            assert f["qop"] == "auth" and f["nc"] == "00000001"
            expected = _h(
                name, f"{ha1}:{self.nonce}:{f['nc']}:{f['cnonce']}:auth:{ha2}"
            )
        else:
            expected = _h(name, f"{ha1}:{self.nonce}:{ha2}")
        return f["uri"] == self.path and f["response"] == expected

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def digest_server() -> Iterator[str]:
    DigestServer.seen = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DigestServer)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


ALGORITHM_QOP = [
    (algorithm, qop)
    for algorithm in ("", "MD5", "MD5-sess", "SHA", "SHA-256")
    for qop in ("", 'qop="auth", ', 'qop="auth-int, auth", ')
    # MD5-sess without qop cannot be answered, see test_digest_challenge_not_answerable
    if qop or algorithm != "MD5-sess"
]


@pytest.mark.parametrize(("algorithm", "qop"), ALGORITHM_QOP)
def test_digest_algorithms_and_qop(
    digest_server: str, monkeypatch: pytest.MonkeyPatch, algorithm: str, qop: str
) -> None:
    named = f", algorithm={algorithm}" if algorithm else ""
    monkeypatch.setattr(
        DigestServer,
        "challenge",
        f'Digest realm="wptest", {qop}nonce="{{nonce}}", opaque="op"{named}',
    )
    r = check_url(make(f"{digest_server}/x/y?q=1", PASSWORD, username=USER))
    assert r.response_code == 200
    assert [h.split(" ")[0] for h in DigestServer.seen] == ["", "", "Digest"]
    assert 'opaque="op"' in DigestServer.seen[2]


@pytest.mark.parametrize(
    ("challenge", "reason"),
    [
        ('Digest realm="wptest", nonce="{nonce}", algorithm=SHA-512', "algorithm"),
        ('Digest realm="wptest", nonce="{nonce}", qop="auth-int"', "qop auth-int"),
    ],
)
def test_digest_not_answerable_reports_the_401(
    digest_server: str,
    monkeypatch: pytest.MonkeyPatch,
    log_file: Path,
    challenge: str,
    reason: str,
) -> None:
    monkeypatch.setattr(DigestServer, "challenge", challenge)
    results = [
        check_url(make(f"{digest_server}/", PASSWORD, username=USER)) for _ in "ab"
    ]
    assert [r.response_code for r in results] == [401, 401]
    assert DigestServer.seen == [""] * 4, "probe and one request per check"
    warnings = [
        line
        for line in log_file.read_text(encoding="utf-8").splitlines()
        if "Digest challenge cannot be answered" in line
    ]
    assert len(warnings) == 1 and reason in warnings[0]
    assert warnings[0].endswith("; the check reports the 401")


def test_digest_after_a_redirect_names_the_final_uri(
    digest_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 401 comes from the redirect's target: the response answers for it."""

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", f"{digest_server}/after/redirect")
            self.send_header("Content-Length", "0")
            self.end_headers()

        @override
        def log_message(self, format: str, *args: object) -> None:
            pass

    monkeypatch.setattr(
        DigestServer, "challenge", 'Digest realm="wptest", qop=auth, nonce="{nonce}"'
    )
    front = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    try:
        r = check_url(
            make(
                f"http://127.0.0.1:{front.server_address[1]}/", PASSWORD, username=USER
            )
        )
    finally:
        front.shutdown()
        front.server_close()
    assert r.response_code == 200
    assert 'uri="/after/redirect"' in DigestServer.seen[-1]


def test_digest_credentials_are_never_logged(
    digest_server: str, monkeypatch: pytest.MonkeyPatch, log_file: Path
) -> None:
    monkeypatch.setattr(
        DigestServer, "challenge", 'Digest realm="wptest", qop=auth, nonce="{nonce}"'
    )
    assert (
        check_url(make(f"{digest_server}/", PASSWORD, username=USER)).response_code
        == 200
    )
    text = log_file.read_text(encoding="utf-8")
    assert "site offers authentication scheme digest" in text
    assert PASSWORD not in text and "Digest username" not in text
