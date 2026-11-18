"""Which proxy each request of a check goes through, and the urllib handler that
sends it there.

A proxy set in website_monitoring.conf (proxy_server) carries every request of the
inputs that use its stanza, redirects included; proxy_ignore and NO_PROXY do not
apply to it, as in Website Monitoring. Without one, the proxies of the process
environment apply (HTTP_PROXY for http URLs, HTTPS_PROXY for https URLs), except for
hosts listed in NO_PROXY or in the stanza's proxy_ignore.

The environment is only read, never changed. Website Monitoring wrote proxy_ignore
into NO_PROXY for the whole process, so the stanza that ran last decided for all
the others.
"""

from __future__ import annotations

import base64
import ipaddress
import urllib.request
import weakref
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Union
from urllib.parse import quote, unquote, urlsplit

from logger import StanzaLogger
from wp_splunk import PROXY_REALM, PROXY_USERNAME, SOCKS_PROXY_TYPES, ProxyConf

HTTP_PROXY_TYPE = "http"
DEFAULT_PROXY_PORT = "80"
"""Website Monitoring built http://<server>:<port>; with a blank port that is
http://<server>:, which means port 80."""

DIRECT = "direct"
FROM_CONF = "conf"
FROM_ENVIRONMENT = "env"

_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class UnsupportedProxyError(Exception):
    """The route of a request names a proxy this input cannot use. The message is
    the event's error value."""


@dataclass(frozen=True)
class ProxyEndpoint:
    """A proxy URL taken apart; user and password are decoded."""

    scheme: str
    hostport: str
    user: str = ""
    password: str = field(default="", repr=False)


@dataclass(frozen=True)
class ProxyRoute:
    """How one request goes out: directly, or through the proxy at url."""

    via: str
    """DIRECT, FROM_CONF or FROM_ENVIRONMENT."""
    url: str = field(default="", repr=False)
    """The proxy URL, with percent-encoded credentials if it has any."""
    configuration: str = ""
    """The website_monitoring.conf stanza of a FROM_CONF route."""
    error: str = ""
    """Set when the request must not be sent."""

    def endpoint(self) -> ProxyEndpoint:
        return parse_proxy_url(self.url)

    def describe(self) -> str:
        """For the log: the route without the proxy password."""
        if self.error:
            return f"refused: {self.error}"
        if self.via == DIRECT:
            return DIRECT
        endpoint = self.endpoint()
        text = f"{endpoint.scheme}://{endpoint.hostport}"
        if endpoint.user:
            text += f" user={endpoint.user}"
        if self.via == FROM_CONF:
            return f"{FROM_CONF} {self.configuration} {text}"
        return f"{self.via} {text}"


DIRECT_ROUTE = ProxyRoute(DIRECT)


def conf_proxy_url(proxy: ProxyConf, password: str | None) -> str:
    """http://[user:password@]server:port of a configured proxy.

    User and password are percent-encoded, so an @, : or % in either reaches the
    proxy unchanged. Credentials are added only when both are set.
    """
    server = proxy.proxy_server
    if ":" in server and not server.startswith("["):
        server = f"[{server}]"  # an IPv6 address
    credentials = ""
    if proxy.proxy_user and password:
        credentials = f"{quote(proxy.proxy_user, safe='')}:{quote(password, safe='')}@"
    port = proxy.proxy_port or DEFAULT_PROXY_PORT
    return f"http://{credentials}{server}:{port}"


def parse_proxy_url(url: str) -> ProxyEndpoint:
    """Take apart [scheme://][user[:password]@]host[:port][/...], as urllib reads
    proxy URLs: no scheme means http."""
    scheme, separator, rest = url.partition("://")
    if not separator:
        scheme, rest = HTTP_PROXY_TYPE, url
    authority = rest.split("/", 1)[0]
    userinfo, at, hostport = authority.rpartition("@")
    if not at:
        userinfo, hostport = "", authority
    user, _, password = userinfo.partition(":")
    return ProxyEndpoint(
        scheme.lower(), unquote(hostport), unquote(user), unquote(password)
    )


def split_hosts(text: str) -> list[str]:
    return [name.strip() for name in text.split(",") if name.strip()]


def _address(host: str) -> _Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _network(name: str) -> _Network | None:
    try:
        return ipaddress.ip_network(name, strict=False)
    except ValueError:
        return None


def bypassed(host: str, port: int | None, names: Sequence[str]) -> bool:
    """Whether a request to host (and port) skips the environment proxy.

    names are NO_PROXY entries as urllib matches them: * for every host; a name
    for itself and its subdomains (a leading dot is ignored); host:port for that
    port only. Like requests, an IP address also matches a network in CIDR form.
    """
    host = host.lower()
    hostport = host if port is None else f"{host}:{port}"
    address = _address(host)
    for raw in names:
        name = raw.strip().lower()
        if not name:
            continue
        if name == "*":
            return True
        if address is not None:
            network = _network(name)
            if network is not None and network.version == address.version:
                if address in network:
                    return True
                continue
        name = name.lstrip(".")
        if name in (host, hostport):
            return True
        if host.endswith("." + name) or hostport.endswith("." + name):
            return True
    return False


def resolve_proxy(
    url: str,
    proxy: ProxyConf,
    proxy_password: str | None,
    env_proxies: Mapping[str, str],
    configuration: str = "default",
) -> ProxyRoute:
    """The route of one request to url.

    proxy is the input's website_monitoring.conf stanza (configuration),
    proxy_password the stored proxy password, env_proxies the environment's
    proxies as urllib.request.getproxies_environment() returns them (scheme to
    URL, "no" to NO_PROXY).
    """
    if proxy.proxy_server:
        kind = proxy.proxy_type.lower()
        if kind == HTTP_PROXY_TYPE:
            return ProxyRoute(
                FROM_CONF, conf_proxy_url(proxy, proxy_password), configuration
            )
        if kind in SOCKS_PROXY_TYPES:
            # Such a stanza is refused when the configuration is read; this only
            # keeps a check from going out directly if one ever got through.
            return ProxyRoute(
                FROM_CONF,
                configuration=configuration,
                error=f"proxy_type = {proxy.proxy_type} is not supported",
            )
        # Any other type: no proxy from the stanza, as in Website Monitoring.
    parts = urlsplit(url)
    env_url = env_proxies.get(parts.scheme.lower(), "")
    if not env_url:
        return DIRECT_ROUTE
    names = split_hosts(env_proxies.get("no", "")) + split_hosts(proxy.proxy_ignore)
    if bypassed(parts.hostname or "", parts.port, names):
        return DIRECT_ROUTE
    endpoint = parse_proxy_url(env_url)
    if endpoint.scheme != HTTP_PROXY_TYPE:
        return ProxyRoute(
            FROM_ENVIRONMENT,
            error=f"proxy scheme {endpoint.scheme} from the environment is not supported",
        )
    if not endpoint.hostport:
        return ProxyRoute(
            FROM_ENVIRONMENT, error="proxy URL from the environment has no host"
        )
    return ProxyRoute(FROM_ENVIRONMENT, env_url)


def proxy_warnings(proxy: ProxyConf, proxy_password: str | None) -> list[str]:
    """What is worth one warning per input about the proxy settings of its stanza.
    Settings that make the stanza unusable are refused when it is read instead."""
    if not proxy.proxy_server:
        return []
    kind = proxy.proxy_type.lower()
    if kind != HTTP_PROXY_TYPE:
        if kind in SOCKS_PROXY_TYPES:
            return []
        message = (
            f"proxy_type {proxy.proxy_type!r} is not recognised; proxy_server is not"
            " used, as in Website Monitoring"
        )
        return [message]
    warnings: list[str] = []
    if not proxy.proxy_port:
        warnings.append(f"proxy_port is blank; using port {DEFAULT_PROXY_PORT}")
    if proxy.proxy_ignore:
        warnings.append(
            "proxy_ignore has no effect on a configured proxy, as in Website Monitoring"
        )
    if proxy.proxy_user and not proxy_password:
        warnings.append(
            "proxy_user is set but no proxy password is stored (realm"
            f" {PROXY_REALM}, user {PROXY_USERNAME}); requests go to the proxy"
            " without credentials"
        )
    return warnings


def basic_credentials(endpoint: ProxyEndpoint) -> str:
    text = f"{endpoint.user}:{endpoint.password}"
    return "Basic " + base64.b64encode(text.encode("utf-8")).decode("ascii")


class ProxyRouteHandler(urllib.request.ProxyHandler):
    """Sends each request through the proxy that route() picks for its URL, or
    directly; on every hop, redirects included.

    Takes the place of urllib's ProxyHandler (and so of the default one that
    build_opener would add), which skips any proxy, a configured one too, for the
    hosts in the process's NO_PROXY. Like it, it runs before the HTTP and HTTPS
    handlers: it only points the request at the proxy. Proxy credentials go into
    Proxy-Authorization, which urllib moves into the CONNECT request for https.
    """

    def __init__(self, route: Callable[[str], ProxyRoute], log: StanzaLogger) -> None:
        super().__init__({})
        self.route: Callable[[str], ProxyRoute] = route
        self.log: StanzaLogger = log
        self._routed: weakref.WeakSet[urllib.request.Request] = weakref.WeakSet()

    def http_open(self, req: urllib.request.Request) -> None:
        self._apply(req)

    def https_open(self, req: urllib.request.Request) -> None:
        self._apply(req)

    def _apply(self, req: urllib.request.Request) -> None:
        # set_proxy changes the request's host; a request sent again (an
        # authentication retry) keeps the route it already has.
        if req in self._routed:
            return
        self._routed.add(req)
        route = self.route(req.full_url)
        self.log.debug("route to %s: %s", req.host, route.describe())
        if route.error:
            raise UnsupportedProxyError(route.error)
        if route.via == DIRECT:
            return
        endpoint = route.endpoint()
        if endpoint.user:
            req.add_unredirected_header(
                "Proxy-Authorization", basic_credentials(endpoint)
            )
        req.set_proxy(endpoint.hostport, HTTP_PROXY_TYPE)
