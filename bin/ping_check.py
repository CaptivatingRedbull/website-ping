from __future__ import annotations

import http.client
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import IO, Optional, cast

from compat import override
from logger import log
from ping_config import Settings
from ping_events import FieldValue

CHUNK_SIZE = 64 * 1024
MAX_ERROR_LENGTH = 200


@dataclass(frozen=True)
class CheckResult:
    response_code: int
    total_time: float
    timed_out: bool = False
    error: str = ""


class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow at most max_redirects redirects, then let the 3xx surface as an HTTPError."""

    def __init__(self, max_redirects: int) -> None:
        self.max_redirects: int = max_redirects
        self.followed: int = 0
        self.limit_reached: bool = False

    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        if self.followed >= self.max_redirects:
            self.limit_reached = True
            return None
        self.followed += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _drain(response: IO[bytes], deadline: float) -> bool:
    """Read and discard the body. False if the deadline passed or a read timed out."""
    while True:
        try:
            chunk = response.read(CHUNK_SIZE)
        except (socket.timeout, TimeoutError):
            return False
        if not chunk:
            return True
        if time.monotonic() > deadline:
            return False


def _fetch(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    timeout: int,
    deadline: float,
) -> tuple[int, bool]:
    """Return (status code, body completely read). Transport errors propagate."""
    try:
        response = cast(http.client.HTTPResponse, opener.open(request, timeout=timeout))
        with response:
            return int(response.status), _drain(response, deadline)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, _drain(exc, deadline)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]


def check_url(settings: Settings) -> CheckResult:
    redirects = LimitedRedirectHandler(settings["max_redirects"])
    # ProxyHandler({}) ignores proxy environment variables (will be implemented later)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirects)
    request = urllib.request.Request(
        settings["url"], headers={"User-Agent": settings["user_agent"]}, method="GET"
    )
    timeout = settings["timeout"]
    start = time.monotonic()
    deadline = start + timeout

    def result(code: int, timed_out: bool = False, error: str = "") -> CheckResult:
        return CheckResult(code, round(time.monotonic() - start, 3), timed_out, error)

    try:
        code, complete = _fetch(opener, request, timeout, deadline)
    except (socket.timeout, TimeoutError):
        return result(0, timed_out=True)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            return result(0, timed_out=True)
        detail = exc.reason if isinstance(exc.reason, BaseException) else exc
        return result(0, error=_describe(detail))
    except (OSError, http.client.HTTPException) as exc:
        return result(0, error=_describe(exc))
    except Exception as exc:
        log.exception("unexpected error during check")
        return result(0, error="unexpected " + _describe(exc))
    if not complete:
        return result(code, timed_out=True)
    if redirects.limit_reached and 300 <= code <= 400:
        return result(
            code, error=f"redirect limit of {settings['max_redirects']} reached"
        )
    return result(code)


def event_fields(settings: Settings, result: CheckResult) -> dict[str, FieldValue]:
    fields: dict[str, FieldValue] = {
        "title": settings["title"],
        "url": settings["url"],
        "response_code": result.response_code,
        "total_time": result.total_time,
        "timed_out": result.timed_out,
    }
    if result.error:
        fields["error"] = result.error
    return fields
