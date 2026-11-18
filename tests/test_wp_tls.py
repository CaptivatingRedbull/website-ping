"""SSL contexts of a check, against loopback TLS servers with generated certificates."""

from __future__ import annotations

import logging
import re
import socket
import ssl
import subprocess
import sys
import threading
import warnings
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import logger
import ping_check
import pytest
from compat import override
from ping_check import check_url
from ping_config import build_settings
from wp_context import CheckContext, make_context
from wp_splunk import Configuration
from wp_tls import (
    NO_CA_BUNDLE,
    ContextCache,
    TLSOptions,
    TLSSetupError,
    find_ca_bundle,
    require_tls12,
    unverified_context,
    verifying_context,
)
from wptest import certs
from wptest.contract import ERROR_PATTERNS

HOST = "localhost"
"""Resolves to the loopback address; the certificates are issued for it."""


def _openssl(folder: Path, *args: str) -> None:
    _ = subprocess.run(["openssl", *args], cwd=folder, check=True, capture_output=True)


def _sign(folder: Path, name: str, issuer: str, extensions: str, serial: str) -> None:
    _openssl(
        folder,
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
        "-keyout", f"{name}.key", "-out", f"{name}.csr",
    )  # fmt: skip
    (folder / f"{name}.ext").write_text(extensions)
    _openssl(
        folder,
        "x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.pem",
        "-CAkey", f"{issuer}.key", "-set_serial", serial, "-days", "2",
        "-extfile", f"{name}.ext", "-out", f"{name}.pem",
    )  # fmt: skip


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> certs.Certificates:
    """The harness certificates for HOST, plus:

    no-aki.pem: a server certificate without an authority key identifier, which
    Python 3.13's default X.509 checks reject;
    chain.pem: a server certificate issued by intermediate.pem (issued by the CA),
    sent with the intermediate."""
    folder = tmp_path_factory.mktemp("pki")
    generated = certs.generate(folder, HOST)
    server = (
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        f"subjectAltName = DNS:{HOST}\n"
    )
    _sign(folder, "no-aki", "ca", server + "authorityKeyIdentifier = none\n", "2001")
    intermediate = (
        "basicConstraints = critical, CA:TRUE, pathlen:0\n"
        "keyUsage = critical, keyCertSign, cRLSign\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid:always\n"
    )
    _sign(folder, "intermediate", "ca", intermediate, "2002")
    _sign(
        folder,
        "leaf",
        "intermediate",
        server + "authorityKeyIdentifier = keyid\n",
        "2003",
    )
    (folder / "chain.pem").write_text(
        (folder / "leaf.pem").read_text() + (folder / "intermediate.pem").read_text()
    )
    return generated


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        _ = self.wfile.write(b"ok")

    @override
    def log_message(self, format: str, *args: object) -> None:
        pass


class TLSServer(ThreadingHTTPServer):
    """HTTPS on the loopback address with one certificate; counts connections."""

    daemon_threads = True

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.context: ssl.SSLContext = context
        self.connections: int = 0

    @override
    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        conn, address = super().get_request()
        self.connections += 1
        return self.context.wrap_socket(conn, server_side=True), address

    @override
    def handle_error(self, request: object, client_address: object) -> None:
        pass  # failed handshakes are what most tests are about

    @property
    def url(self) -> str:
        return f"https://{HOST}:{self.server_address[1]}/"


def server_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return context


def tls11_context(cert: Path, key: Path) -> ssl.SSLContext:
    """A server that speaks nothing newer than TLS 1.1."""
    context = server_context(cert, key)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


@pytest.fixture(scope="session")
def servers(pki: certs.Certificates) -> Iterator[dict[str, TLSServer]]:
    folder = pki.folder
    contexts = {
        name: server_context(folder / f"{name}.pem", folder / f"{name}.key")
        for name in ("valid", "expired", "self-signed", "wrong-host", "no-aki")
    }
    contexts["chain"] = server_context(folder / "chain.pem", folder / "leaf.key")
    contexts["tls11"] = tls11_context(folder / "valid.pem", folder / "valid.key")
    running = {name: TLSServer(context) for name, context in contexts.items()}
    for server in running.values():
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield running
    for server in running.values():
        server.shutdown()
        server.server_close()


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    """Records logged by the input while the test runs."""
    collected: list[logging.LogRecord] = []

    class Collect(logging.Handler):
        @override
        def emit(self, record: logging.LogRecord) -> None:
            collected.append(record)

    handler = Collect()
    logger.log.addHandler(handler)
    yield collected
    logger.log.removeHandler(handler)


def make(
    url: str, configuration: Configuration | None = None, **extra: str
) -> CheckContext:
    settings, _ = build_settings(
        "web_ping://tls", {"url": url, "interval": "60", **extra}
    )
    return make_context(settings, configuration or Configuration())


def verified(url: str, ca: Path) -> CheckContext:
    return make(url, ssl_verify="1", ca_certs=str(ca))


# ---- verification off (the default) -----------------------------------------


@pytest.mark.parametrize("name", ["valid", "expired", "self-signed", "wrong-host"])
def test_default_accepts_any_certificate(
    servers: dict[str, TLSServer], name: str
) -> None:
    r = check_url(make(servers[name].url))
    assert r.response_code == 200 and r.error == ""


@pytest.mark.parametrize("name", ["expired", "self-signed", "wrong-host"])
def test_verification_off_ignores_ca_certs(
    servers: dict[str, TLSServer], name: str
) -> None:
    r = check_url(make(servers[name].url, ssl_verify="0", ca_certs="/nonexistent.pem"))
    assert r.response_code == 200 and r.error == ""


def test_unverified_context_is_explicit() -> None:
    context = unverified_context()
    assert context.verify_mode == ssl.CERT_NONE and not context.check_hostname


# ---- verification on ----------------------------------------------------------


def test_valid_certificate_with_ca_certs(
    servers: dict[str, TLSServer], pki: certs.Certificates
) -> None:
    r = check_url(verified(servers["valid"].url, pki.ca))
    assert r.response_code == 200 and r.error == ""


@pytest.mark.parametrize(
    ("name", "pattern"),
    [
        ("expired", "Expired certificate"),
        ("self-signed", "Self-signed certificate"),
        ("wrong-host", "Wrong hostname"),
    ],
)
def test_bad_certificates_fail(
    monkeypatch: pytest.MonkeyPatch,
    servers: dict[str, TLSServer],
    pki: certs.Certificates,
    name: str,
    pattern: str,
) -> None:
    # What splunk-launch.conf's PYTHONHTTPSVERIFY=0 does to Splunk's Python:
    # urllib's implicit context stops checking certificates. The check's own
    # context must not care.
    unverified = ssl._create_unverified_context  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("PYTHONHTTPSVERIFY", "0")
    monkeypatch.setattr(ssl, "_create_default_https_context", unverified)
    r = check_url(verified(servers[name].url, pki.ca))
    assert r.response_code is None and not r.timed_out
    assert re.search(ERROR_PATTERNS[pattern], r.error), r.error


def test_verification_on_from_the_configuration(
    servers: dict[str, TLSServer], pki: certs.Certificates
) -> None:
    on = Configuration(ssl_verify=True, ca_certs=str(pki.ca))
    assert check_url(make(servers["valid"].url, on)).response_code == 200
    r = check_url(make(servers["expired"].url, on))
    assert r.error == "SSLCertVerificationError: certificate has expired"


@pytest.mark.parametrize("value", ["0", "false"])
def test_input_ssl_verify_wins_over_the_configuration(
    servers: dict[str, TLSServer], pki: certs.Certificates, value: str
) -> None:
    on = Configuration(ssl_verify=True, ca_certs=str(pki.ca))
    r = check_url(make(servers["expired"].url, on, ssl_verify=value))
    assert r.response_code == 200 and r.error == ""


def test_input_ca_certs_wins_over_the_configuration(
    servers: dict[str, TLSServer], pki: certs.Certificates, tmp_path: Path
) -> None:
    on = Configuration(ssl_verify=True, ca_certs=str(tmp_path / "absent.pem"))
    r = check_url(make(servers["valid"].url, on, ca_certs=str(pki.ca)))
    assert r.response_code == 200 and r.error == ""


def test_certificate_error_is_the_verification_result(
    servers: dict[str, TLSServer], pki: certs.Certificates
) -> None:
    r = check_url(verified(servers["expired"].url, pki.ca))
    assert r.error == "SSLCertVerificationError: certificate has expired"


def test_missing_ca_certs_sends_nothing(
    servers: dict[str, TLSServer], records: list[logging.LogRecord]
) -> None:
    server = servers["valid"]
    before = server.connections
    settings = verified(server.url, Path("/nonexistent/wp-ca.pem"))
    first, second = check_url(settings), check_url(settings)
    for r in (first, second):
        assert r.response_code is None and not r.timed_out
        assert r.error == "ca_certs not readable: /nonexistent/wp-ca.pem"
    assert server.connections == before
    errors = [rec for rec in records if rec.levelno == logging.ERROR]
    assert len(errors) == 1, "logged once, not for every check"


def test_ca_certs_without_certificates(
    servers: dict[str, TLSServer], tmp_path: Path
) -> None:
    empty = tmp_path / "empty.pem"
    empty.write_text("no certificates here\n")
    r = check_url(verified(servers["valid"].url, empty))
    assert r.response_code is None
    assert r.error.startswith(f"ca_certs has no usable certificate: {empty}")


def test_ca_certs_only_matters_for_https(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        r = check_url(verified(url, tmp_path / "missing.pem"))
    finally:
        server.shutdown()
        server.server_close()
    assert r.response_code == 200 and r.error == ""


# ---- CA bundle without ca_certs -----------------------------------------------


def test_bundle_from_ssl_cert_file(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("")
    other = tmp_path / "other.pem"
    other.write_text("")
    environ = {"SSL_CERT_FILE": str(bundle)}
    assert find_ca_bundle(environ, [str(other)]) == str(bundle)


def test_bundle_skips_missing_files(tmp_path: Path) -> None:
    second = tmp_path / "second.pem"
    second.write_text("")
    environ = {"SSL_CERT_FILE": str(tmp_path / "absent.pem")}
    candidates = [str(tmp_path / "first.pem"), str(second)]
    assert find_ca_bundle(environ, candidates) == str(second)


def test_no_bundle() -> None:
    assert find_ca_bundle({}, []) is None


def test_verification_with_the_found_bundle(
    monkeypatch: pytest.MonkeyPatch,
    servers: dict[str, TLSServer],
    pki: certs.Certificates,
    records: list[logging.LogRecord],
) -> None:
    cache = ContextCache({}, [str(pki.folder / "absent.pem"), str(pki.ca)])
    monkeypatch.setattr(ping_check, "CONTEXTS", cache)
    settings = make(servers["valid"].url, ssl_verify="true", log_level="DEBUG")
    assert check_url(settings).response_code == 200
    assert check_url(settings).response_code == 200
    used = [rec for rec in records if str(pki.ca) in rec.getMessage()]
    assert len(used) == 1 and used[0].levelno == logging.DEBUG


def test_verification_without_any_bundle(
    monkeypatch: pytest.MonkeyPatch, servers: dict[str, TLSServer]
) -> None:
    monkeypatch.setattr(ping_check, "CONTEXTS", ContextCache({}, []))
    server = servers["valid"]
    before = server.connections
    r = check_url(make(server.url, ssl_verify="true"))
    assert r.response_code is None and r.error == NO_CA_BUNDLE
    assert server.connections == before


def test_unusable_bundle(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.pem"
    bundle.write_text("no certificates here\n")
    cache = ContextCache({}, [str(bundle)])
    log = logger.stanza_logger("web_ping://tls")
    with pytest.raises(TLSSetupError, match=f"^CA bundle not usable: {bundle} "):
        _ = cache.get(TLSOptions(verify=True), log)


def test_failure_is_kept(pki: certs.Certificates) -> None:
    cache = ContextCache({}, [])
    options = TLSOptions(verify=True)
    log = logger.stanza_logger("web_ping://tls")
    for _ in range(2):
        with pytest.raises(TLSSetupError, match=NO_CA_BUNDLE):
            _ = cache.get(options, log)
    assert cache.get(TLSOptions(verify=True, ca_certs=str(pki.ca)), log) is cache.get(
        TLSOptions(verify=True, ca_certs=str(pki.ca)), log
    )


# ---- the same result on Python 3.9 and 3.13 -----------------------------------


def test_certificate_without_authority_key_identifier(
    servers: dict[str, TLSServer], pki: certs.Certificates
) -> None:
    r = check_url(verified(servers["no-aki"].url, pki.ca))
    assert r.response_code == 200 and r.error == ""


def test_intermediate_alone_is_not_a_trust_anchor(
    servers: dict[str, TLSServer], pki: certs.Certificates
) -> None:
    url = servers["chain"].url
    assert check_url(verified(url, pki.ca)).response_code == 200
    r = check_url(verified(url, pki.folder / "intermediate.pem"))
    assert r.response_code is None
    assert r.error.startswith("SSLCertVerificationError: unable to get"), r.error


@pytest.mark.skipif(sys.version_info < (3, 13), reason="checks of Python 3.13")
@pytest.mark.parametrize(
    ("name", "ca"), [("no-aki", "ca.pem"), ("chain", "intermediate.pem")]
)
def test_python_default_differs_on_3_13(
    servers: dict[str, TLSServer], pki: certs.Certificates, name: str, ca: str
) -> None:
    """The two cases above do differ with Python's own default context."""
    context = ssl.create_default_context(cafile=str(pki.folder / ca))
    port = servers[name].server_address[1]
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        if name == "no-aki":
            with pytest.raises(ssl.SSLCertVerificationError, match="Authority Key"):
                _ = context.wrap_socket(raw, server_hostname=HOST)
        else:
            context.wrap_socket(raw, server_hostname=HOST).close()


def test_no_stricter_flags(pki: certs.Certificates) -> None:
    flags = verifying_context(str(pki.ca)).verify_flags
    assert not flags & ssl.VERIFY_X509_STRICT
    assert not flags & getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)


# ---- TLS 1.2 minimum ------------------------------------------------------------


@pytest.mark.parametrize("verify", ["0", "1"])
def test_tls11_server_is_refused(
    servers: dict[str, TLSServer], pki: certs.Certificates, verify: str
) -> None:
    r = check_url(make(servers["tls11"].url, ssl_verify=verify, ca_certs=str(pki.ca)))
    assert r.response_code is None and not r.timed_out
    assert re.search(ERROR_PATTERNS["TLS handshake failed"], r.error), r.error


def test_protocol_options_without_minimum_version(
    servers: dict[str, TLSServer],
) -> None:
    """The fallback for OpenSSL 1.0.2, where minimum_version cannot be set."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        require_tls12(context, settable=False)
    assert context.options & ssl.OP_NO_TLSv1 and context.options & ssl.OP_NO_TLSv1_1
    port = servers["tls11"].server_address[1]
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    with raw, pytest.raises(ssl.SSLError):
        _ = context.wrap_socket(raw, server_hostname=HOST)


def test_tls12_is_accepted(servers: dict[str, TLSServer]) -> None:
    r = check_url(make(servers["valid"].url))
    assert r.response_code == 200
