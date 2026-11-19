"""wp_proxy: the route of each request, and checks through a loopback forwarding
and CONNECT proxy."""

from __future__ import annotations

import base64
import http.client
import logging
import os
import socket
import ssl
import threading
import time
import warnings
from collections.abc import Iterator, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast
from urllib.parse import urlsplit

import logger
import pytest
from compat import override
from ping_check import NO_PROXY, ProxyInfo, check_url
from ping_config import build_settings
from wp_context import CheckContext, make_context
from wp_deadline import Phases
from wp_proxy import (
    DIRECT_ROUTE,
    ProxyEndpoint,
    bypassed,
    conf_proxy_url,
    parse_proxy_url,
    proxy_warnings,
    resolve_proxy,
)
from wp_splunk import Configuration, ProxyConf
from wptest import certs

HOST = "localhost"
"""The targets' name; the proxy is reached as 127.0.0.1, so a TLS name check
that passes for HOST checked the target, not the proxy."""
USER = "wp@user"
PASSWORD = "p@ss:w%rd"
"""Characters that break a proxy URL unless user and password are percent-encoded."""

SQUID = ProxyConf(proxy_server="squid", proxy_port="3128")
ENV = {"http": "http://envproxy:3128", "https": "http://envproxy:3129"}


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# ---- resolve_proxy ------------------------------------------------------------


def _conf(**values: str) -> ProxyConf:
    return ProxyConf(**{"proxy_server": "squid", "proxy_port": "3128", **values})


def _env(**values: str) -> dict[str, str]:
    return {**ENV, **values}


ROUTES: list[tuple[str, str, ProxyConf, str | None, Mapping[str, str], tuple[str, str]]] = [
    ("conf-http", "http://target/", SQUID, None, {}, ("conf", "http://squid:3128")),
    ("conf-https", "https://target/", SQUID, None, {}, ("conf", "http://squid:3128")),
    ("conf-blank-port", "http://target/", ProxyConf(proxy_server="squid"), None, {},
     ("conf", "http://squid:80")),
    ("conf-type-case", "http://target/", _conf(proxy_type="HTTP"), None, {},
     ("conf", "http://squid:3128")),
    ("conf-over-proxy-ignore", "http://target/", _conf(proxy_ignore="target"), None, {},
     ("conf", "http://squid:3128")),
    ("conf-over-proxy-ignore-star", "http://target/", _conf(proxy_ignore="*"), None, {},
     ("conf", "http://squid:3128")),
    ("conf-over-no-proxy", "http://target/", SQUID, None, _env(no="target"),
     ("conf", "http://squid:3128")),
    ("conf-over-env", "https://target/", SQUID, None, ENV, ("conf", "http://squid:3128")),
    ("conf-credentials", "http://target/", _conf(proxy_user="wpproxy"), "secret", {},
     ("conf", "http://wpproxy:secret@squid:3128")),
    ("conf-user-no-password", "http://target/", _conf(proxy_user="wpproxy"), None, {},
     ("conf", "http://squid:3128")),
    ("conf-password-no-user", "http://target/", SQUID, "secret", {},
     ("conf", "http://squid:3128")),
    ("conf-ipv6", "http://target/", _conf(proxy_server="fd00::1"), None, {},
     ("conf", "http://[fd00::1]:3128")),
    ("unknown-type-takes-env", "http://target/", _conf(proxy_type="ftp"), None, ENV,
     ("env", "http://envproxy:3128")),
    ("unknown-type-direct", "http://target/", _conf(proxy_type="ftp"), None, {},
     ("direct", "")),
    ("no-proxy-set", "http://target/", ProxyConf(), None, {}, ("direct", "")),
    ("env-http", "http://target/", ProxyConf(), None, ENV, ("env", "http://envproxy:3128")),
    ("env-https", "https://target/", ProxyConf(), None, ENV,
     ("env", "http://envproxy:3129")),
    ("env-http-not-for-https", "https://target/", ProxyConf(), None,
     {"http": "http://envproxy:3128"}, ("direct", "")),
    ("env-without-scheme", "http://target/", ProxyConf(), None, {"http": "envproxy:3128"},
     ("env", "envproxy:3128")),
    ("no-proxy-exact", "http://target:8080/", ProxyConf(), None, _env(no="x,target"),
     ("direct", "")),
    ("no-proxy-suffix", "http://a.example.com/", ProxyConf(), None,
     _env(no="example.com"), ("direct", "")),
    ("no-proxy-dot", "http://a.example.com/", ProxyConf(), None, _env(no=".example.com"),
     ("direct", "")),
    ("no-proxy-not-a-label", "http://notexample.com/", ProxyConf(), None,
     _env(no="example.com"), ("env", "http://envproxy:3128")),
    ("no-proxy-port", "http://target:8080/", ProxyConf(), None, _env(no="target:8080"),
     ("direct", "")),
    ("no-proxy-other-port", "http://target:8081/", ProxyConf(), None,
     _env(no="target:8080"), ("env", "http://envproxy:3128")),
    ("no-proxy-star", "http://target/", ProxyConf(), None, _env(no="*"), ("direct", "")),
    ("no-proxy-case", "http://TARGET/", ProxyConf(), None, _env(no="Target"),
     ("direct", "")),
    ("no-proxy-ip", "http://192.0.2.10/", ProxyConf(), None, _env(no="192.0.2.10"),
     ("direct", "")),
    ("no-proxy-cidr", "http://10.1.2.3/", ProxyConf(), None, _env(no="10.0.0.0/8"),
     ("direct", "")),
    ("no-proxy-cidr-miss", "http://192.168.1.1/", ProxyConf(), None,
     _env(no="10.0.0.0/8"), ("env", "http://envproxy:3128")),
    ("no-proxy-ipv6-cidr", "http://[fd00::5]/", ProxyConf(), None, _env(no="fd00::/8"),
     ("direct", "")),
    ("proxy-ignore-exact", "http://target/", ProxyConf(proxy_ignore="target"), None, ENV,
     ("direct", "")),
    ("proxy-ignore-suffix", "http://a.example.com/",
     ProxyConf(proxy_ignore=" x , example.com "), None, ENV, ("direct", "")),
    ("proxy-ignore-star", "https://env-proxied/", ProxyConf(proxy_ignore="*"), None,
     ENV, ("direct", "")),
    ("proxy-ignore-plus-no-proxy-1", "http://a.test/", ProxyConf(proxy_ignore="b.test"),
     None, _env(no="a.test"), ("direct", "")),
    ("proxy-ignore-plus-no-proxy-2", "http://b.test/", ProxyConf(proxy_ignore="b.test"),
     None, _env(no="a.test"), ("direct", "")),
    ("proxy-ignore-miss", "http://c.test/", ProxyConf(proxy_ignore="b.test"), None,
     _env(no="a.test"), ("env", "http://envproxy:3128")),
]  # fmt: skip


@pytest.mark.parametrize(
    ("url", "proxy", "password", "env_proxies", "expected"),
    [row[1:] for row in ROUTES],
    ids=[row[0] for row in ROUTES],
)
def test_resolve_proxy(
    url: str,
    proxy: ProxyConf,
    password: str | None,
    env_proxies: Mapping[str, str],
    expected: tuple[str, str],
) -> None:
    route = resolve_proxy(url, proxy, password, env_proxies, "cfg")
    assert (route.via, route.url) == expected
    assert route.error == ""


@pytest.mark.parametrize(
    ("proxy", "env_proxies", "error"),
    [
        (ProxyConf(), {"http": "socks5://envproxy:1080"},
         "proxy scheme socks5 from the environment is not supported"),
        (ProxyConf(), {"http": "https://envproxy:3128"},
         "proxy scheme https from the environment is not supported"),
        (ProxyConf(), {"http": "http://"}, "proxy URL from the environment has no host"),
        (_conf(proxy_type="socks5"), {}, "proxy_type = socks5 is not supported"),
    ],
    ids=["env-socks", "env-https-proxy", "env-no-host", "conf-socks"],
)  # fmt: skip
def test_routes_that_cannot_be_used(
    proxy: ProxyConf, env_proxies: Mapping[str, str], error: str
) -> None:
    assert resolve_proxy("http://target/", proxy, None, env_proxies).error == error


def test_empty_names_and_hosts_do_not_match() -> None:
    assert not bypassed("target", None, ["", " ", ","])
    assert not bypassed("", None, ["target"])


def test_credentials_are_percent_encoded_and_decoded_back() -> None:
    proxy = _conf(proxy_port="3129", proxy_user="wp@user:x")
    password = "p@ss:w%rd/ä"
    url = conf_proxy_url(proxy, password)
    assert url == "http://wp%40user%3Ax:p%40ss%3Aw%25rd%2F%C3%A4@squid:3129"
    assert parse_proxy_url(url) == ProxyEndpoint(
        "http", "squid:3129", "wp@user:x", password
    )


def test_describe_never_shows_the_password() -> None:
    route = resolve_proxy(
        "http://t/",
        _conf(proxy_port="3129", proxy_user="wpproxy"),
        "secret",
        {},
        "auth",
    )
    assert route.describe() == "conf auth http://squid:3129 user=wpproxy"
    env = resolve_proxy(
        "http://t/", ProxyConf(), None, {"http": "http://u:secret@sq:1"}
    )
    assert env.describe() == "env http://sq:1 user=u"
    assert DIRECT_ROUTE.describe() == "direct"
    for shown in (repr(route), repr(env), repr(route.endpoint())):
        assert "secret" not in shown


@pytest.mark.parametrize(
    ("proxy", "password", "expected"),
    [
        (ProxyConf(), None, []),
        (ProxyConf(proxy_ignore="*", proxy_user="u"), None, []),
        (SQUID, None, []),
        (_conf(proxy_type="socks5"), None, []),
        (ProxyConf(proxy_server="squid"), None, ["proxy_port is blank; using port 80"]),
        (_conf(proxy_ignore="target"), None,
         ["proxy_ignore has no effect on a configured proxy, as in Website Monitoring"]),
        (_conf(proxy_user="wpproxy"), "stored", []),
        (_conf(proxy_user="wpproxy"), None,
         [("proxy_user is set but no proxy password is stored (realm"
           " website_monitoring_app_proxy, user IN_CONF_FILE); requests go to the proxy"
           " without credentials")]),
        (_conf(proxy_type="ftp", proxy_ignore="x"), None,
         [("proxy_type 'ftp' is not recognised; proxy_server is not used, as in"
           " Website Monitoring")]),
    ],
    ids=["none", "no-server", "plain", "socks", "blank-port", "ignore", "user-stored",
         "user-no-password", "unknown-type"],
)  # fmt: skip
def test_proxy_warnings(
    proxy: ProxyConf, password: str | None, expected: list[str]
) -> None:
    assert proxy_warnings(proxy, password) == expected


def test_http_client_names_the_deadline_connections_use() -> None:
    """DeadlineHTTP(S)Connection hook into these two attributes of http.client."""
    connection = http.client.HTTPSConnection("proxy.invalid", 3128)
    assert callable(vars(connection)["_create_connection"])
    assert vars(connection)["_tunnel_host"] is None
    connection.set_tunnel("target.invalid:8443")
    assert vars(connection)["_tunnel_host"] == "target.invalid"


# ---- through a loopback proxy -------------------------------------------------


class TargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        server = cast("Target", self.server)
        server.requests.append(
            (self.path, {k.lower(): v for k, v in self.headers.items()})
        )
        if self.path.startswith("/redirect?to="):
            self.send_response(302)
            self.send_header("Location", self.path.split("=", 1)[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/trickle":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            for _ in range(1000):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            _ = self.wfile.write(b"ok")

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


class Target(ThreadingHTTPServer):
    """A loopback HTTP or HTTPS server that records each request's path and headers."""

    daemon_threads = True

    def __init__(self, context: ssl.SSLContext | None = None) -> None:
        super().__init__(("127.0.0.1", 0), TargetHandler)
        self.context: ssl.SSLContext | None = context
        self.requests: list[tuple[str, dict[str, str]]] = []

    @override
    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        conn, address = super().get_request()
        if self.context is None:
            return conn, address
        return self.context.wrap_socket(conn, server_side=True), address

    @override
    def handle_error(self, request: object, client_address: object) -> None:
        pass  # refused handshakes and cut connections are what some tests are about

    def url(self, path: str, host: str = HOST) -> str:
        scheme = "https" if self.context else "http"
        return f"{scheme}://{host}:{self.server_address[1]}{path}"


def _read_head(conn: socket.socket) -> tuple[str, list[tuple[str, str]], bytes] | None:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    line, *fields = head.decode("latin-1").split("\r\n")
    headers = [(name.strip(), value.strip()) for name, _, value in
               (field.partition(":") for field in fields)]  # fmt: skip
    return line, headers, rest


def _pipe(source: socket.socket, sink: socket.socket) -> None:
    try:
        while chunk := source.recv(65536):
            sink.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class LocalProxy:
    """A forwarding proxy on 127.0.0.1: absolute-form requests for http, CONNECT
    tunnels for https. Records the request line and headers it receives.

    credentials: the user:password it requires, else 407. stall: "connect" never
    answers a CONNECT; "tunnel" answers it, then never opens the tunnel."""

    def __init__(self, credentials: str | None = None, stall: str = "") -> None:
        self.credentials: str | None = credentials
        self.stall: str = stall
        self.heads: list[tuple[str, dict[str, str]]] = []
        self.stop: threading.Event = threading.Event()
        self.listener: socket.socket = socket.create_server(("127.0.0.1", 0))
        self.port: int = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def conf(self, **values: str) -> ProxyConf:
        return ProxyConf(proxy_server="127.0.0.1", proxy_port=str(self.port), **values)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            head = _read_head(conn)
            if head is None:
                return
            line, fields, rest = head
            headers = {name.lower(): value for name, value in fields}
            self.heads.append((line, headers))
            if self.credentials is not None and headers.get(
                "proxy-authorization"
            ) != basic(*self.credentials.split(":", 1)):
                conn.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="wptest"\r\n'
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            method, target, _ = line.split(" ", 2)
            if method == "CONNECT":
                if self.stall == "connect":
                    _ = self.stop.wait(30)
                    return
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if self.stall == "tunnel":
                    _ = self.stop.wait(30)
                    return
                host, _, port = target.rpartition(":")
                upstream = socket.create_connection((host, int(port)), timeout=10)
                first = rest
            else:
                url = urlsplit(target)
                upstream = socket.create_connection(
                    (url.hostname or "", url.port or 80), timeout=10
                )
                path = url.path + (f"?{url.query}" if url.query else "")
                kept = [f"{name}: {value}" for name, value in fields
                        if name.lower() not in ("proxy-authorization", "proxy-connection")]  # fmt: skip
                first = "\r\n".join([f"{method} {path} HTTP/1.1", *kept]) + "\r\n\r\n"
                first = first.encode("latin-1") + rest
            with upstream:
                upstream.sendall(first)
                back = threading.Thread(
                    target=_pipe, args=(upstream, conn), daemon=True
                )
                back.start()
                _pipe(conn, upstream)
                back.join(15)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        self.listener.close()


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> certs.Certificates:
    return certs.generate(tmp_path_factory.mktemp("pki"), HOST)


def _server_context(pki: certs.Certificates, name: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        str(pki.folder / f"{name}.pem"), str(pki.folder / f"{name}.key")
    )
    return context


def _start(server: Target) -> Target:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def http_target() -> Iterator[Target]:
    server = _start(Target())
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def tls_targets(pki: certs.Certificates) -> Iterator[dict[str, Target]]:
    tls11 = _server_context(pki, "valid")  # speaks nothing newer than TLS 1.1
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        tls11.minimum_version = ssl.TLSVersion.TLSv1
        tls11.maximum_version = ssl.TLSVersion.TLSv1_1
    tls11.set_ciphers("DEFAULT:@SECLEVEL=0")
    contexts = {
        "valid": _server_context(pki, "valid"),
        "self-signed": _server_context(pki, "self-signed"),
        "tls11": tls11,
    }
    servers = {name: _start(Target(context)) for name, context in contexts.items()}
    yield servers
    for server in servers.values():
        server.shutdown()
        server.server_close()


@pytest.fixture
def proxies() -> Iterator[list[LocalProxy]]:
    """Proxies a test opens; closed after it."""
    opened: list[LocalProxy] = []
    yield opened
    for proxy in opened:
        proxy.close()


def open_proxy(proxies: list[LocalProxy], **options: str) -> LocalProxy:
    proxy = LocalProxy(**options)
    proxies.append(proxy)
    return proxy


def make(
    url: str,
    proxy: ProxyConf | None = None,
    proxy_password: str | None = None,
    **extra: str,
) -> CheckContext:
    settings, _ = build_settings(
        "web_ping://proxy", {"url": url, "interval": "60", **extra}
    )
    configuration = Configuration(proxy=proxy or ProxyConf())
    return make_context(settings, configuration, proxy_password=proxy_password)


def test_http_through_the_configured_proxy_with_credentials(
    http_target: Target, proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies, credentials=f"{USER}:{PASSWORD}")
    url = http_target.url("/plain")
    r = check_url(make(url, proxy.conf(proxy_user=USER), PASSWORD))
    assert (r.response_code, r.error) == (200, "")
    assert r.proxy == ProxyInfo("127.0.0.1", "http", str(proxy.port), USER)
    [(line, headers)] = proxy.heads
    assert line == f"GET {url} HTTP/1.1"
    assert headers["proxy-authorization"] == basic(USER, PASSWORD)
    [(path, received)] = http_target.requests
    assert (
        path == "/plain"
        and received["host"] == f"{HOST}:{http_target.server_address[1]}"
    )


def test_https_through_a_tunnel_with_credentials_and_verification(
    tls_targets: dict[str, Target], pki: certs.Certificates, proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies, credentials=f"{USER}:{PASSWORD}")
    target = tls_targets["valid"]
    context = make(
        target.url("/tunnel"),
        proxy.conf(proxy_user=USER),
        PASSWORD,
        ssl_verify="true",
        ca_certs=str(pki.ca),
    )
    r = check_url(context)
    # The certificate names only HOST: verification passing means the handshake
    # checked the target's name through the tunnel, not the proxy's address.
    assert (r.response_code, r.error) == (200, "")
    [(line, headers)] = proxy.heads
    assert line.startswith(f"CONNECT {HOST}:{target.server_address[1]} HTTP/1.")
    assert headers["proxy-authorization"] == basic(USER, PASSWORD)
    [(path, received)] = target.requests
    assert path == "/tunnel" and "proxy-authorization" not in received


@pytest.mark.parametrize(
    ("name", "verify", "code", "error"),
    [
        ("self-signed", "false", 200, ""),
        ("self-signed", "true", None, "SSLCertVerificationError: "),
        ("tls11", "false", None, "SSLError: "),
    ],
    ids=["unverified", "verified", "tls-1.1"],
)
def test_the_tunnel_uses_the_checks_tls_context(
    tls_targets: dict[str, Target],
    pki: certs.Certificates,
    proxies: list[LocalProxy],
    name: str,
    verify: str,
    code: int | None,
    error: str,
) -> None:
    """Verification on or off and the TLS 1.2 minimum apply behind the proxy."""
    proxy = open_proxy(proxies)
    target = tls_targets[name]
    context = make(
        target.url("/"), proxy.conf(), ssl_verify=verify, ca_certs=str(pki.ca)
    )
    r = check_url(context)
    assert r.response_code == code and r.error.startswith(error)
    assert error or r.error == ""
    assert [line.split(" ")[0] for line, _ in proxy.heads] == ["CONNECT"]


@pytest.mark.parametrize("stall", ["connect", "tunnel"])
def test_expiry_ends_a_stalled_tunnel(
    tls_targets: dict[str, Target], proxies: list[LocalProxy], stall: str
) -> None:
    """A proxy that never answers the CONNECT, or never opens the tunnel so the
    TLS handshake waits: only the expiry (the runner's tick) can end the check
    before the 30 s socket timeout."""
    proxy = open_proxy(proxies, stall=stall)
    phases = Phases()
    timer = threading.Timer(0.5, phases.stop)
    timer.start()
    try:
        r = check_url(make(tls_targets["valid"].url("/"), proxy.conf()), phases)
    finally:
        timer.join()
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2


def test_expiry_ends_a_stalled_direct_handshake() -> None:
    listener = socket.create_server(("127.0.0.1", 0))
    accepted: list[socket.socket] = []
    threading.Thread(
        target=lambda: accepted.append(listener.accept()[0]), daemon=True
    ).start()
    phases = Phases()
    timer = threading.Timer(0.5, phases.stop)
    timer.start()
    try:
        port = listener.getsockname()[1]
        r = check_url(make(f"https://127.0.0.1:{port}/"), phases)
    finally:
        timer.join()
        for conn in accepted:
            conn.close()
        listener.close()
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2


def test_stalled_tunnel_ends_at_the_timeout(
    tls_targets: dict[str, Target], proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies, stall="tunnel")
    r = check_url(make(tls_targets["valid"].url("/"), proxy.conf(), timeout="1"))
    assert r.timed_out and r.response_code is None
    assert r.elapsed < 1.8


def test_expiry_ends_a_trickle_through_the_tunnel(
    tls_targets: dict[str, Target], proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies)
    phases = Phases()
    timer = threading.Timer(1.0, phases.stop)
    timer.start()
    try:
        r = check_url(make(tls_targets["valid"].url("/trickle"), proxy.conf()), phases)
    finally:
        timer.join()
    assert r.timed_out and r.response_code is None and r.error == ""
    assert r.elapsed < 2.5
    assert proxy.heads and proxy.heads[0][0].startswith("CONNECT ")


def test_missing_proxy_credentials(
    http_target: Target, tls_targets: dict[str, Target], proxies: list[LocalProxy]
) -> None:
    """For http the proxy's 407 is the response; for https the tunnel fails."""
    proxy = open_proxy(proxies, credentials="wpproxy:secret")
    r = check_url(make(http_target.url("/"), proxy.conf(proxy_user="wpproxy")))
    assert r.response_code == 407
    r = check_url(make(tls_targets["valid"].url("/"), proxy.conf()))
    assert r.response_code is None
    assert (
        r.error
        == "OSError: Tunnel connection failed: 407 Proxy Authentication Required"
    )
    assert http_target.requests == [] and tls_targets["valid"].requests == []


def test_environment_proxy_without_a_configured_one(
    monkeypatch: pytest.MonkeyPatch, http_target: Target, proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies)
    monkeypatch.setenv("http_proxy", proxy.url)
    before = dict(os.environ)
    r = check_url(make(http_target.url("/env")))
    assert (r.response_code, r.error) == (200, "")
    assert r.proxy == NO_PROXY
    assert [line for line, _ in proxy.heads] == [
        f"GET {http_target.url('/env')} HTTP/1.1"
    ]
    assert dict(os.environ) == before


@pytest.mark.parametrize("ignore", [HOST, "*"])
def test_proxy_ignore_bypasses_the_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
    http_target: Target,
    proxies: list[LocalProxy],
    ignore: str,
) -> None:
    proxy = open_proxy(proxies)
    monkeypatch.setenv("http_proxy", proxy.url)
    monkeypatch.setenv("no_proxy", "other.invalid")
    before = dict(os.environ)
    r = check_url(make(http_target.url("/direct"), ProxyConf(proxy_ignore=ignore)))
    assert (r.response_code, r.error) == (200, "")
    assert proxy.heads == [] and len(http_target.requests) == 1
    assert dict(os.environ) == before


def test_configured_proxy_ignores_no_proxy_and_proxy_ignore(
    monkeypatch: pytest.MonkeyPatch, http_target: Target, proxies: list[LocalProxy]
) -> None:
    proxy = open_proxy(proxies)
    monkeypatch.setenv("no_proxy", HOST)
    before = dict(os.environ)
    r = check_url(make(http_target.url("/conf"), proxy.conf(proxy_ignore=HOST)))
    assert (r.response_code, r.error) == (200, "")
    assert len(proxy.heads) == 1
    assert dict(os.environ) == before


def test_every_hop_takes_its_own_route(
    monkeypatch: pytest.MonkeyPatch, http_target: Target, proxies: list[LocalProxy]
) -> None:
    """The first hop goes through the environment proxy, the redirect to a host in
    NO_PROXY goes directly."""
    proxy = open_proxy(proxies)
    monkeypatch.setenv("http_proxy", proxy.url)
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    second = http_target.url("/second", host="127.0.0.1")
    r = check_url(make(http_target.url(f"/redirect?to={second}")))
    assert (r.response_code, r.error) == (200, "")
    assert len(proxy.heads) == 1
    assert [path for path, _ in http_target.requests] == [
        f"/redirect?to={second}",
        "/second",
    ]


def test_unsupported_environment_proxy_is_an_error_event(
    monkeypatch: pytest.MonkeyPatch, http_target: Target
) -> None:
    monkeypatch.setenv("http_proxy", "socks5://127.0.0.1:1080")
    r = check_url(make(http_target.url("/")))
    assert r.response_code is None and not r.timed_out
    assert r.error == "proxy scheme socks5 from the environment is not supported"
    assert http_target.requests == []


def test_route_is_logged_at_debug_without_the_password(
    http_target: Target, proxies: list[LocalProxy]
) -> None:
    collected: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        @override
        def emit(self, record: logging.LogRecord) -> None:
            collected.append(record)

    proxy = open_proxy(proxies, credentials=f"{USER}:{PASSWORD}")
    context = make(
        http_target.url("/"), proxy.conf(proxy_user=USER), PASSWORD, log_level="DEBUG"
    )
    handler = Collect()
    logger.log.addHandler(handler)
    try:
        _ = check_url(context)
    finally:
        logger.log.removeHandler(handler)
    messages = [record.getMessage() for record in collected]
    route = (
        f"route to {HOST}:{http_target.server_address[1]}: conf default"
        f" http://127.0.0.1:{proxy.port} user={USER}"
    )
    assert [m for m in messages if m.startswith("route ")] == [route]
    assert all(PASSWORD not in m for m in messages)
