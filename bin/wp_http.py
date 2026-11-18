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
from collections.abc import Callable
from typing import IO, Optional, cast
from urllib.parse import urlsplit

from compat import override
from wp_deadline import Deadline
from wp_url import HostNameError, redirect_url

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
FOLLOWED_METHODS = frozenset({"GET", "HEAD"})
_NOT_COPIED = frozenset({"content-length", "content-type", "host"})
MIN_SOCKET_TIMEOUT = 0.01
"""A socket timeout of 0 would switch the socket to non-blocking mode."""

ACCEPT_ENCODING = "gzip, deflate"
ACCEPT = "*/*"
_FIRST_HEADERS = ("Host", "User-agent", "Accept-encoding", "Accept", "Connection")
"""In urllib's spelling (str.capitalize); http.client sends them title-cased."""


def request_headers(user_agent: str) -> dict[str, str]:
    """The headers every request of a check carries, besides Host and Connection,
    which urllib adds to each hop."""
    return {
        "User-Agent": user_agent,
        "Accept-Encoding": ACCEPT_ENCODING,
        "Accept": ACCEPT,
    }


def order_headers(req: urllib.request.Request) -> None:
    """Fix the order the headers go out in: Host, User-Agent, Accept-Encoding,
    Accept, Connection, the request's other headers, then the headers added for
    this hop only (Cookie, Authorization), the order Website Monitoring sent.

    urllib sends the hop-only headers first and then sets Connection: close,
    which keeps the position of a key that is already there. So all headers go
    into the hop-only ones in the wanted order; req.headers stays as it is,
    since a redirect copies those.
    """
    values = {**req.headers, **req.unredirected_hdrs, "Connection": "close"}
    ordered = {name: values.pop(name) for name in _FIRST_HEADERS if name in values}
    ordered.update((name, values.pop(name)) for name in req.headers if name in values)
    ordered.update(values)
    req.unredirected_hdrs = ordered


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
        location = headers.get("Location") or headers.get("URI") or newurl
        try:
            target = redirect_url(req.full_url, location)
        except HostNameError:
            fp.close()
            raise
        self.followed += 1
        same_host = urlsplit(req.full_url).hostname == urlsplit(target).hostname
        kept = {
            name: value
            for name, value in req.headers.items()
            if name.lower() not in _NOT_COPIED
            and (same_host or name.lower() != "authorization")
        }
        # GET and HEAD carry no body, so 301/302/303 (body dropped) and 307/308
        # (method and body kept) all repeat the method without a body.
        return urllib.request.Request(
            target,
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

    def create_connection(
        self,
        address: tuple[str, int],
        timeout: float | None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        """socket.create_connection, with the new socket registered before anything
        is sent on it: expiry then also ends a CONNECT exchange with a proxy."""
        sock = socket.create_connection(address, timeout, source_address)
        self.add(sock)
        return sock

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
        # http.client opens its socket through this attribute (Python 3.9 to 3.13).
        self._create_connection = sockets.create_connection

    @override
    def connect(self) -> None:
        self.timeout = self.sockets.timeout(self.timeout)
        super().connect()


class DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int | None,
        timeout: float | None,
        source_address: tuple[str, int] | None,
        blocksize: int,
        sockets: DeadlineSockets,
        context: ssl.SSLContext,
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
        self.ssl_context: ssl.SSLContext = context
        # http.client opens its socket through this attribute (Python 3.9 to 3.13).
        self._create_connection = sockets.create_connection

    @override
    def connect(self) -> None:
        """HTTPSConnection.connect with the handshake split from the wrap.

        wrap_socket detaches the plain socket before its handshake, so a socket
        registered before the wrap no longer reaches the connection. Here the
        plain socket is registered as it is created (covering the CONNECT exchange
        with a proxy), the TLS socket before its handshake: expiry ends a stalled
        handshake too, directly and through a proxy tunnel. The handshake checks
        the target's name, not the proxy's.
        """
        self.timeout = self.sockets.timeout(self.timeout)
        http.client.HTTPConnection.connect(self)
        tunnel_host = cast(Optional[str], getattr(self, "_tunnel_host", None))
        sock = self.ssl_context.wrap_socket(
            self.sock,
            server_hostname=tunnel_host or self.host,
            do_handshake_on_connect=False,
        )
        self.sock = sock
        self.sockets.add(sock)
        sock.do_handshake()


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, sockets: DeadlineSockets) -> None:
        super().__init__()
        self.sockets: DeadlineSockets = sockets

    @override
    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        order_headers(req)
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
    """HTTPS with the context that context() returns, asked for when the first
    HTTPS connection of a check opens. An exception from context() ends the
    check before anything is sent; a plain-HTTP check never calls it."""

    def __init__(
        self, sockets: DeadlineSockets, context: Callable[[], ssl.SSLContext]
    ) -> None:
        super().__init__()
        self.sockets: DeadlineSockets = sockets
        self.context: Callable[[], ssl.SSLContext] = context
        self.ssl_context: ssl.SSLContext | None = None

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        order_headers(req)
        return self.do_open(self._connection, req)

    def _current_context(self) -> ssl.SSLContext:
        if self.ssl_context is None:
            self.ssl_context = self.context()
        return self.ssl_context

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
            self._current_context(),
        )
