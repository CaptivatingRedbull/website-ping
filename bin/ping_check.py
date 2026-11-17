from __future__ import annotations

import errno
import http.client
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol, cast

from logger import stanza_logger
from ping_config import UNLIMITED_REDIRECTS, Settings
from wp_deadline import Deadline
from wp_http import (
    DeadlineHTTPHandler,
    DeadlineHTTPSHandler,
    DeadlineSockets,
    LimitedRedirectHandler,
)

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


class _Body(Protocol):
    def read1(self, n: int = ..., /) -> bytes: ...


def _drain(response: _Body, deadline: Deadline, sockets: DeadlineSockets) -> bool:
    """Read and discard the body. False if the deadline passed or expired first."""
    while True:
        if deadline.passed():
            return False
        sockets.tighten()
        try:
            chunk = response.read1(CHUNK_SIZE)
        except (socket.timeout, TimeoutError):
            return False
        if not chunk:
            # Expiry shuts the socket down, which a body without a length would
            # otherwise take for its regular end.
            return not deadline.expired


def _fetch(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    timeout: int,
    deadline: Deadline,
    sockets: DeadlineSockets,
) -> tuple[int, bool]:
    """Return (status code, body completely read). Transport errors propagate."""
    try:
        response = cast(http.client.HTTPResponse, opener.open(request, timeout=timeout))
        with response:
            return response.status, _drain(response, deadline, sockets)
    except urllib.error.HTTPError as exc:
        with exc:
            # HTTPError hands attribute access on to the response it wraps.
            return exc.code, _drain(cast(_Body, exc), deadline, sockets)


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
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]


def check_url(settings: Settings, deadline: Deadline | None = None) -> CheckResult:
    """Run one check within deadline, by default the stanza's timeout from now.

    The deadline covers connecting, every redirect, the headers and the body. Any
    failure once the deadline has expired is a timeout."""
    slog = stanza_logger(settings["stanza"], settings["log_level"])
    max_redirects = settings["max_redirects"]
    if max_redirects is None:
        max_redirects = UNLIMITED_REDIRECTS
    timeout = settings["timeout"]
    start = time.monotonic()
    if deadline is None:
        deadline = Deadline(start + timeout)
    sockets = DeadlineSockets(deadline)
    redirects = LimitedRedirectHandler(max_redirects)
    # ProxyHandler({}) ignores proxy environment variables (will be implemented later)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        DeadlineHTTPHandler(sockets),
        DeadlineHTTPSHandler(sockets),
        redirects,
    )
    request = urllib.request.Request(
        settings["url"], headers={"User-Agent": settings["user_agent"]}, method="GET"
    )

    def result(
        code: int | None,
        *,
        timed_out: bool = False,
        error: str = "",
        exceeded_redirects: bool = False,
    ) -> CheckResult:
        return CheckResult(
            response_code=code,
            elapsed=time.monotonic() - start,
            finished=time.time(),
            timed_out=timed_out,
            error=error,
            exceeded_redirects=exceeded_redirects,
        )

    try:
        code, complete = _fetch(opener, request, timeout, deadline, sockets)
    except Exception as exc:  # noqa: BLE001 - a check must always produce an event
        # After expiry the sockets were shut down under the check: whatever that
        # raised (reset, TLS or protocol error) means the time ran out.
        if deadline.expired or _timed_out(exc):
            return result(None, timed_out=True)
        if isinstance(exc, urllib.error.URLError):
            reason = exc.reason
            detail = reason if isinstance(reason, BaseException) else exc
            return result(None, error=_describe(detail))
        if isinstance(exc, (OSError, http.client.HTTPException)):
            return result(None, error=_describe(exc))
        slog.exception("unexpected error during check")
        return result(None, error="unexpected " + _describe(exc))
    if not complete:
        slog.info("status %d arrived, but the body did not within the timeout", code)
        return result(None, timed_out=True)
    if redirects.limit_reached and 300 <= code < 400:
        return result(
            None,
            exceeded_redirects=True,
            error=f"redirect limit of {max_redirects} reached",
        )
    return result(code)
