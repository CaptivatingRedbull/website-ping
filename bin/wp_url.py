"""Request URLs as Website Monitoring's HTTP library sent them: an international
host name in its ASCII form, everything else percent-encoded where needed.

The URL in the event stays the configured text; only the request uses these.
"""

from __future__ import annotations

import string
import unicodedata
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_SAFE = "!#$%&'()*+,/:;=?@[]~"
"""Reserved characters plus "%", kept as they are when an escape is well formed."""
_SAFE_WITHOUT_PERCENT = "!#$&'()*+,/:;=?@[]~"


class HostNameError(ValueError):
    """The host name has no ASCII form that is certain to be the intended host."""


class _BadEscape(ValueError):
    pass


def prepare_url(url: str) -> str:
    """The URL to send: host in ASCII, path and query percent-encoded, existing
    escapes kept, empty path as "/", fragment dropped (it is never sent).

    Raises HostNameError for a host whose ASCII form cannot be decided here.
    """
    parts = urlsplit(url)
    netloc = _ascii_netloc(parts.netloc)
    path = parts.path or "/"
    return requote(urlunsplit((parts.scheme, netloc, path, parts.query, "")))


def redirect_url(base: str, location: str) -> str:
    """The prepared URL a Location header points to, relative to base.

    http.client hands header values over decoded as Latin-1. Servers almost
    always send UTF-8, so valid UTF-8 bytes are read as UTF-8 before encoding.
    """
    try:
        location = location.encode("latin-1").decode("utf-8")
    except UnicodeError:
        pass
    return prepare_url(urljoin(base, location.strip()))


def requote(url: str) -> str:
    """Percent-encode every character outside the unreserved and reserved sets.

    Escapes of unreserved characters are decoded, other well-formed escapes are
    kept; if any escape is malformed, "%" itself is encoded everywhere.
    """
    try:
        return quote(_unquote_unreserved(url), safe=_SAFE)
    except _BadEscape:
        return quote(url, safe=_SAFE_WITHOUT_PERCENT)


def _unquote_unreserved(url: str) -> str:
    parts = url.split("%")
    for index in range(1, len(parts)):
        digits = parts[index][:2]
        if len(digits) == 2 and digits.isalnum():
            try:
                char = chr(int(digits, 16))
            except ValueError:
                raise _BadEscape(digits) from None
            if char in _UNRESERVED:
                parts[index] = char + parts[index][2:]
            else:
                parts[index] = "%" + parts[index]
        else:
            parts[index] = "%" + parts[index]
    return "".join(parts)


def _ascii_netloc(netloc: str) -> str:
    if netloc.isascii():
        return netloc
    userinfo, at, hostport = netloc.rpartition("@")
    host, colon, port = hostport, "", ""
    if not hostport.startswith("["):
        head, sep, tail = hostport.rpartition(":")
        if sep and all(char in string.digits for char in tail):
            host, colon, port = head, sep, tail
    return f"{userinfo}{at}{ascii_host(host)}{colon}{port}"


def ascii_host(host: str) -> str:
    """The ASCII form of a host name, in lower case for an international one.

    Python encodes with IDNA 2003, current resolvers and browsers with IDNA 2008
    (UTS 46). Both give the same name unless the host holds characters the older
    standard maps away (ß, ς, joiners, compatibility forms such as full-width
    letters). Such a host is refused instead of checking a different one: an
    encoding is accepted only if decoding it gives back the host as written.
    """
    if host.isascii():
        return host
    try:
        encoded = host.encode("idna").decode("ascii")
        decoded = encoded.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise HostNameError(
            f"host name {host!r} is not a valid international host name ({exc})"
        ) from None
    if decoded.lower() != unicodedata.normalize("NFC", host.lower()):
        raise HostNameError(
            f"host name {host!r} contains characters whose ASCII form depends on"
            " the IDNA version (such as ß, ς, joiners or full-width letters);"
            " write the host in its ASCII form (xn--...)"
        )
    return encoded.lower()
