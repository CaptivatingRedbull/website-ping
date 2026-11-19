from __future__ import annotations

import errno
import http.client
import http.cookiejar
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message
from typing import Protocol, cast

from logger import StanzaLogger, stanza_logger
from ping_config import UNLIMITED_REDIRECTS, Settings
from wp_auth import (
    BASIC,
    DIGEST,
    NONE,
    AuthorizationHandler,
    Credentials,
    answer_for,
    basic_authorization,
    credentials,
    detect_scheme,
    digest_answer,
)
from wp_content import (
    MAX_BODY_BYTES,
    BodyDecoder,
    ContentDecodingError,
    ContentHashes,
    content_hashes,
    decode_body,
    header_fields,
    header_value,
    truncate_body,
)
from wp_context import CheckContext
from wp_deadline import Deadline, Phases
from wp_http import (
    DeadlineHTTPHandler,
    DeadlineHTTPSHandler,
    DeadlineSockets,
    LimitedRedirectHandler,
    request_headers,
)
from wp_proxy import ProxyRoute, ProxyRouteHandler, UnsupportedProxyError, resolve_proxy
from wp_splunk import ProxyConf
from wp_tls import CONTEXTS, TLSOptions, TLSSetupError, describe_tls_error
from wp_url import HostNameError, prepare_url

CHUNK_SIZE = 64 * 1024
MAX_ERROR_LENGTH = 200


@dataclass(frozen=True)
class ProxyInfo:
    """The proxy settings an event reports, as written in website_monitoring.conf."""

    server: str = ""
    type: str = "http"
    port: str = ""
    user: str = ""


NO_PROXY = ProxyInfo()
"""What Website Monitoring reported when no proxy was configured."""


def proxy_info(proxy: ProxyConf) -> ProxyInfo:
    """The proxy fields of the input's website_monitoring.conf stanza, as written
    there, whether a request went through that proxy, an environment proxy or
    none: Website Monitoring reported the stanza."""
    return ProxyInfo(
        server=proxy.proxy_server,
        type=proxy.proxy_type,
        port=proxy.proxy_port,
        user=proxy.proxy_user,
    )


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one check. response_code is None when no complete response
    arrived (timeout, connection or TLS failure, redirect limit)."""

    response_code: int | None
    elapsed: float
    """Seconds from the start of the request until the body was read."""
    finished: float
    """Wall-clock time (epoch seconds) when the check ended."""
    timed_out: bool = False
    error: str = ""
    exceeded_redirects: bool = False
    headers: tuple[tuple[str, str], ...] | None = None
    """Response headers in the order received, when return_headers is set."""
    content_md5: str | None = None
    content_sha224: str | None = None
    content_size: int | None = None
    has_expected_string: bool | None = None
    proxy: ProxyInfo = NO_PROXY
    body: str | None = None
    """Response body for the body event, when return_body is set."""


@dataclass(frozen=True)
class ResponseContent:
    """What a check takes from a complete response besides its status."""

    hashes: ContentHashes
    has_expected_string: bool | None
    """None when the stanza sets no should_contain_string."""
    headers: tuple[tuple[str, str], ...] | None
    """Only with return_headers."""
    body: str | None
    """Text of the body event; only with return_body and a limit other than 0."""


def response_content(
    settings: Settings, body_limit: int, headers: Message, raw: bytes | bytearray
) -> ResponseContent:
    """Decode and hash the body (the decoded body after any Content-Encoding);
    take the expected string, the headers and the body event's text only as far
    as the stanza asks for them. body_limit is max_response_body_length."""
    text = decode_body(raw, header_value(headers, "Content-Type"))
    needle = settings["should_contain_string"]
    return ResponseContent(
        hashes=content_hashes(text),
        has_expected_string=None if needle is None else needle in text,
        headers=header_fields(headers) if settings["return_headers"] else None,
        body=truncate_body(text, body_limit) if settings["return_body"] else None,
    )


class _Body(Protocol):
    def read1(self, n: int = ..., /) -> bytes: ...


def _read_body(
    response: _Body,
    content_encoding: str | None,
    deadline: Deadline,
    sockets: DeadlineSockets,
) -> BodyDecoder | None:
    """Read and decode the body, up to MAX_BODY_BYTES decoded. None if the
    deadline passed or expired first. Raises ContentDecodingError."""
    decoder = BodyDecoder(content_encoding)
    while not decoder.full:
        if deadline.passed():
            return None
        sockets.tighten()
        try:
            chunk = response.read1(CHUNK_SIZE)
        except (socket.timeout, TimeoutError):
            return None
        if not chunk:
            # Expiry shuts the socket down, which a body without a length would
            # otherwise take for its regular end.
            if deadline.expired:
                return None
            decoder.finish()
            break
        decoder.feed(chunk)
    return decoder


@dataclass(frozen=True)
class _Response:
    status: int
    url: str
    """The URL of the request that got this response, after redirects."""
    headers: Message
    body: BodyDecoder | None
    """None if the body did not arrive in time."""


def _fetch(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    timeout: int,
    deadline: Deadline,
    sockets: DeadlineSockets,
) -> _Response:
    """The final response (after redirects) with its decoded body. Transport and
    decoding errors propagate."""
    try:
        response = cast(http.client.HTTPResponse, opener.open(request, timeout=timeout))
        with response:
            encoding = header_value(response.headers, "Content-Encoding")
            body = _read_body(response, encoding, deadline, sockets)
            return _Response(response.status, response.url, response.headers, body)
    except urllib.error.HTTPError as exc:
        with exc:
            encoding = header_value(exc.headers, "Content-Encoding")
            # HTTPError hands attribute access on to the response it wraps.
            body = _read_body(cast(_Body, exc), encoding, deadline, sockets)
            return _Response(exc.code, exc.url, exc.headers, body)


def _is_timeout(reason: object) -> bool:
    """A socket timeout, or a connect that the kernel gave up on (ETIMEDOUT)."""
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return True
    return isinstance(reason, OSError) and reason.errno == errno.ETIMEDOUT


def _timed_out(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.URLError):
        return _is_timeout(exc.reason)
    return _is_timeout(exc)


def _describe(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLError):
        text = describe_tls_error(exc)
    else:
        text = f"{type(exc).__name__}: {exc}"
    return text[:MAX_ERROR_LENGTH]


class _MakeOpener(Protocol):
    def __call__(
        self, sockets: DeadlineSockets, *handlers: urllib.request.BaseHandler
    ) -> urllib.request.OpenerDirector: ...


def _probe(
    opener: _MakeOpener,
    url: str,
    settings: Settings,
    max_redirects: int,
    phases: Phases,
) -> Message:
    """The headers of the final response to a request without credentials, sent
    the way the timed request will be (proxy, TLS, redirects), within its own
    timeout. Not measured. Transport errors propagate."""
    timeout = settings["timeout"]
    deadline = phases.start(timeout)
    sockets = DeadlineSockets(deadline)
    request = urllib.request.Request(
        url, headers=request_headers(settings["user_agent"]), method="GET"
    )
    redirects = LimitedRedirectHandler(max_redirects)
    response = _fetch(opener(sockets, redirects), request, timeout, deadline, sockets)
    return response.headers


def _auth_handlers(
    creds: Credentials, url: str, answer: str
) -> tuple[urllib.request.BaseHandler, ...]:
    """Basic credentials go with every request to the checked host; Digest is
    answered after the first 401 (see _digest_round)."""
    if answer != BASIC:
        return ()
    return (AuthorizationHandler(url, basic_authorization(creds)),)


def _digest_round(
    opener: urllib.request.OpenerDirector,
    response: _Response,
    creds: Credentials,
    settings: Settings,
    log: StanzaLogger,
    deadline: Deadline,
    sockets: DeadlineSockets,
) -> _Response:
    """Answer the Digest challenge of a 401 once, within the same deadline and
    through the same opener, so the redirect limit and cookies carry on. A
    second 401 is the result."""
    if response.status != 401 or response.body is None:
        return response
    authorization = digest_answer(
        creds, response.headers, response.url, settings["stanza"], log
    )
    if authorization is None:
        return response
    request = urllib.request.Request(
        response.url, headers=request_headers(settings["user_agent"]), method="GET"
    )
    request.add_unredirected_header("Authorization", authorization)
    return _fetch(opener, request, settings["timeout"], deadline, sockets)


def tls_options(context: CheckContext) -> TLSOptions:
    verify = context.ssl_verify
    certificate = context.settings["client_certificate"]
    return TLSOptions(
        verify=verify,
        ca_certs=context.ca_certs if verify else None,
        client_certificate=certificate,
        client_certificate_key=(
            context.settings["client_certificate_key"] if certificate else None
        ),
    )


def check_url(context: CheckContext, phases: Phases | None = None) -> CheckResult:
    """Run one check. Each phase gets the stanza's timeout from its own start:
    the authentication probe (only with a user name and a stored password), then
    the timed request.

    The timed request's deadline covers connecting, every redirect, the headers
    and the body. Any failure once the deadline has expired is a timeout."""
    settings = context.settings
    slog = stanza_logger(settings["stanza"], settings["log_level"])
    max_redirects = settings["max_redirects"]
    if max_redirects is None:
        max_redirects = UNLIMITED_REDIRECTS
    timeout = settings["timeout"]
    check_phases = phases if phases is not None else Phases()
    tls = tls_options(context)
    env_proxies = urllib.request.getproxies_environment()

    def route(url: str) -> ProxyRoute:
        return resolve_proxy(
            url,
            context.proxy,
            context.proxy_password,
            env_proxies,
            settings["configuration"],
        )

    def opener(
        sockets: DeadlineSockets, *handlers: urllib.request.BaseHandler
    ) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(
            ProxyRouteHandler(route, slog),
            DeadlineHTTPHandler(sockets),
            DeadlineHTTPSHandler(sockets, lambda: CONTEXTS.get(tls, slog)),
            # A new jar per opener: a cookie set during one check's redirects is
            # sent on its later hops, never by the probe, another check or stanza.
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            *handlers,
        )

    start = time.monotonic()

    def result(
        code: int | None,
        *,
        timed_out: bool = False,
        error: str = "",
        exceeded_redirects: bool = False,
        content: ResponseContent | None = None,
    ) -> CheckResult:
        hashes = content.hashes if content else None
        return CheckResult(
            response_code=code,
            elapsed=time.monotonic() - start,
            finished=time.time(),
            timed_out=timed_out,
            error=error,
            exceeded_redirects=exceeded_redirects,
            headers=content.headers if content else None,
            content_md5=hashes.md5 if hashes else None,
            content_sha224=hashes.sha224 if hashes else None,
            content_size=hashes.size if hashes else None,
            has_expected_string=content.has_expected_string if content else None,
            proxy=proxy_info(context.proxy),
            body=content.body if content else None,
        )

    try:
        url = prepare_url(settings["url"])
    except HostNameError as exc:
        return result(None, error=_describe(exc))
    auth: tuple[urllib.request.BaseHandler, ...] = ()
    creds = credentials(settings["username"], context.password)
    answer = NONE
    if creds is not None:
        scheme = detect_scheme(
            lambda: _probe(opener, url, settings, max_redirects, check_phases), slog
        )
        answer = answer_for(scheme, settings["stanza"], slog)

    deadline = check_phases.start(timeout)
    start = time.monotonic()
    sockets = DeadlineSockets(deadline)
    redirects = LimitedRedirectHandler(max_redirects)
    try:
        request = urllib.request.Request(
            url, headers=request_headers(settings["user_agent"]), method="GET"
        )
        auth = _auth_handlers(creds, url, answer) if creds is not None else ()
        timed = opener(sockets, redirects, *auth)
        response = _fetch(timed, request, timeout, deadline, sockets)
        if creds is not None and answer == DIGEST:
            response = _digest_round(
                timed, response, creds, settings, slog, deadline, sockets
            )
    except (TLSSetupError, UnsupportedProxyError) as exc:
        # Raised before the connection of a request opens: nothing was sent.
        return result(None, error=str(exc)[:MAX_ERROR_LENGTH])
    except Exception as exc:  # noqa: BLE001 - a check must always produce an event
        # After expiry the sockets were shut down under the check: whatever that
        # raised (reset, TLS or protocol error) means the time ran out.
        if deadline.expired or _timed_out(exc):
            return result(None, timed_out=True)
        if isinstance(exc, urllib.error.URLError):
            reason = exc.reason
            detail = reason if isinstance(reason, BaseException) else exc
            return result(None, error=_describe(detail))
        if isinstance(
            exc,
            (OSError, http.client.HTTPException, HostNameError, ContentDecodingError),
        ):
            return result(None, error=_describe(exc))
        slog.exception("unexpected error during check")
        return result(None, error="unexpected " + _describe(exc))
    code, body = response.status, response.body
    if body is None:
        slog.info("status %d arrived, but the body did not within the timeout", code)
        return result(None, timed_out=True)
    if body.full:
        slog.warning(
            "body larger than %d MiB; only the first %d MiB are used",
            MAX_BODY_BYTES >> 20,
            MAX_BODY_BYTES >> 20,
        )
    if redirects.limit_reached and 300 <= code < 400:
        return result(
            None,
            exceeded_redirects=True,
            error=f"redirect limit of {max_redirects} reached",
        )
    # Decoding and hashing count towards the response time, as in 2.9.7.
    content = response_content(
        settings, context.max_response_body_length, response.headers, body.body
    )
    return result(code, content=content)
