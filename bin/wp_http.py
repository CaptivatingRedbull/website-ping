"""urllib building blocks for one check: redirects as Website Monitoring followed
them, and connections that end when the check's deadline expires."""

from __future__ import annotations

import http.client
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
from typing import IO
from urllib.parse import urlsplit

from compat import override
from wp_deadline import Deadline

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
FOLLOWED_METHODS = frozenset({"GET", "HEAD"})
_NOT_COPIED = frozenset({"content-length", "content-type", "host"})
MIN_SOCKET_TIMEOUT = 0.01
"""A socket timeout of 0 would switch the socket to non-blocking mode."""


class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow at most limit redirects; on the next one, let the 3xx surface as an
    HTTPError and set limit_reached.

    The limit is the only one: urllib's own limits (10 redirects, 4 repeats of one
    URL) are raised above it, and a redirect loop simply runs into the limit, as
    with requests. One handler per check, since it counts the redirects followed.
    """

    # urllib checks these after redirect_request has accepted a redirect, so they
    # must never be reached: redirect_request already stops at the limit.
    max_redirections = sys.maxsize
    max_repeats = sys.maxsize

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit: int = limit
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
    ) -> urllib.request.Request | None:
        method = req.get_method()
        if code not in REDIRECT_CODES or method not in FOLLOWED_METHODS:
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        if self.followed >= self.limit:
            self.limit_reached = True
            return None
        self.followed += 1
        same_host = urlsplit(req.full_url).hostname == urlsplit(newurl).hostname
        kept = {
            name: value
            for name, value in req.headers.items()
            if name.lower() not in _NOT_COPIED
            and (same_host or name.lower() != "authorization")
        }
        # GET and HEAD carry no body, so 301/302/303 (body dropped) and 307/308
        # (method and body kept) all repeat the method without a body.
        return urllib.request.Request(
            newurl,
            headers=kept,
            origin_req_host=req.origin_req_host,
            unverifiable=True,
            method=method,
        )

    # Python 3.9 has no hook for 308 (added in 3.11); handle it like the others.
    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302


class DeadlineSockets:
    """The sockets one check opens, bounded by the check's deadline.

    Every connection waits at most until the deadline. When the deadline expires,
    all sockets are shut down, which ends a read that is blocked in another thread
    (a socket timeout only bounds each single read, not a slow trickle of them).
    """

    def __init__(self, deadline: Deadline) -> None:
        self.deadline: Deadline = deadline
        self._lock: threading.Lock = threading.Lock()
        self._sockets: list[socket.socket] = []
        self._shut: bool = False
        deadline.on_expire(self.shutdown_all)

    def timeout(self, configured: float | None) -> float:
        """The timeout for a new connection: the time left, at most configured."""
        remaining = self.deadline.remaining()
        if remaining <= 0:
            raise socket.timeout("the check's deadline has passed")
        # None (no timeout) or urllib's "global default" marker when the opener
        # was called without a timeout: only the deadline applies.
        if not isinstance(configured, (int, float)):
            return remaining
        return max(MIN_SOCKET_TIMEOUT, min(configured, remaining))

    def add(self, sock: socket.socket) -> None:
        with self._lock:
            if not self._shut:
                self._sockets.append(sock)
                return
        _shutdown(sock)

    def tighten(self) -> None:
        """Let the next read on any open socket wait no longer than the time left."""
        timeout = max(MIN_SOCKET_TIMEOUT, self.deadline.remaining())
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            if sock.fileno() != -1:
                try:
                    sock.settimeout(timeout)
                except OSError:
                    pass

    def shutdown_all(self) -> None:
        with self._lock:
            self._shut = True
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            _shutdown(sock)


def _shutdown(sock: socket.socket) -> None:
    # The plain socket's shutdown, also for TLS sockets: SSLSocket.shutdown would
    # drop the TLS state under a read running in another thread. Shutting down
    # the descriptor makes that read return or fail; the check then reports a
    # timeout. A socket that is already closed raises OSError, which is fine.
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass


class DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        host: str,
        port: int | None,
        timeout: float | None,
        source_address: tuple[str, int] | None,
        blocksize: int,
        sockets: DeadlineSockets,
    ) -> None:
        super().__init__(host, port, timeout, source_address, blocksize)
        self.sockets: DeadlineSockets = sockets

    @override
    def connect(self) -> None:
        self.timeout = self.sockets.timeout(self.timeout)
        super().connect()
        self.sockets.add(self.sock)


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int | None,
        timeout: float | None,
        source_address: tuple[str, int] | None,
        blocksize: int,
        sockets: DeadlineSockets,
        context: ssl.SSLContext | None,
    ) -> None:
        super().__init__(
            host,
            port,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )
        self.sockets: DeadlineSockets = sockets

    @override
    def connect(self) -> None:
        # The TLS handshake runs inside super().connect(), bounded by the timeout
        # set here; the socket is registered once it is wrapped.
        self.timeout = self.sockets.timeout(self.timeout)
        super().connect()
        self.sockets.add(self.sock)


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, sockets: DeadlineSockets) -> None:
        super().__init__()
        self.sockets: DeadlineSockets = sockets

    @override
    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(self._connection, req)

    def _connection(
        self,
        host: str,
        /,
        *,
        port: int | None = None,
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> http.client.HTTPConnection:
        return DeadlineHTTPConnection(
            host, port, timeout, source_address, blocksize, self.sockets
        )


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(
        self, sockets: DeadlineSockets, context: ssl.SSLContext | None = None
    ) -> None:
        super().__init__()
        self.sockets: DeadlineSockets = sockets
        self.ssl_context: ssl.SSLContext | None = context

    @override
    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(self._connection, req)

    def _connection(
        self,
        host: str,
        /,
        *,
        port: int | None = None,
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        blocksize: int = 8192,
    ) -> http.client.HTTPConnection:
        return DeadlineHTTPSConnection(
            host,
            port,
            timeout,
            source_address,
            blocksize,
            self.sockets,
            self.ssl_context,
        )
