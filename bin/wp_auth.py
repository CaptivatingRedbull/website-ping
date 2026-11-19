"""HTTP authentication of a check, as Website Monitoring chose it.

With a user name and a stored password, a check first sends one request without
credentials and reads the scheme from the WWW-Authenticate headers of the answer.
That request is not part of the measured time. The timed request then sends Basic
credentials up front, or answers the site's Digest challenge once. NTLM and
Negotiate are not supported: the request goes out without credentials and the
site's 401 is the result.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import threading
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from email.message import Message
from urllib.parse import urlsplit
from urllib.request import parse_http_list, parse_keqv_list

from logger import StanzaLogger

BASIC = "basic"
DIGEST = "digest"
NTLM = "ntlm"
NEGOTIATE = "negotiate"
NONE = "none"
"""Send no credentials."""

_FIRST_TOKEN = re.compile(r"\s*([A-Za-z0-9]+)")
"""Website Monitoring took the first run of letters and digits as the scheme."""

DIGEST_HASHES: Mapping[str, str] = {
    "MD5": "md5",
    "MD5-SESS": "md5",
    "SHA": "sha1",
    "SHA-256": "sha256",
}
"""Digest algorithms answered (upper case) and their hashlib names."""


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str = field(repr=False)


def credentials(username: str | None, password: str | None) -> Credentials | None:
    """Both are needed; with only one of them nothing is sent, as in Website
    Monitoring."""
    if username is None or password is None:
        return None
    return Credentials(username, password)


def challenges(headers: Message) -> list[str]:
    """Every WWW-Authenticate header of a response, in the order received."""
    return [str(value) for value in headers.get_all("WWW-Authenticate") or []]


def scheme_of(offered: Sequence[str]) -> str:
    """The scheme to answer, lower-cased: ntlm if any header names NTLM (as in
    "Negotiate, NTLM"), otherwise the first word of the first header. basic when
    there is no header or its first word is not a name."""
    if any(NTLM in value.lower() for value in offered):
        return NTLM
    if not offered:
        return BASIC
    match = _FIRST_TOKEN.match(offered[0])
    return match.group(1).lower() if match else BASIC


def detect_scheme(probe: Callable[[], Message], log: StanzaLogger) -> str:
    """Send the probe and read the scheme from its response headers. Any failure
    of the probe means basic, as in Website Monitoring; the timed request then
    shows whether the site is reachable."""
    try:
        headers = probe()
    except Exception as exc:  # noqa: BLE001 - the probe must never end the check
        log.warning(
            "could not ask the site for its authentication scheme, using basic: %s",
            _short(exc),
        )
        return BASIC
    offered = challenges(headers)
    scheme = scheme_of(offered)
    if offered:
        log.debug("site offers authentication scheme %s", scheme)
    else:
        log.debug("site sent no WWW-Authenticate header, using basic")
    return scheme


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:200]


class WarnOnce:
    """Warnings logged once per stanza and kind for the life of the process.
    Checks run on several threads, so the set is guarded."""

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._seen: set[tuple[str, str]] = set()

    def first(self, stanza: str, kind: str) -> bool:
        with self._lock:
            if (stanza, kind) in self._seen:
                return False
            self._seen.add((stanza, kind))
            return True


WARNED = WarnOnce()


def answer_for(scheme: str, stanza: str, log: StanzaLogger) -> str:
    """How the timed request authenticates for the scheme the site offers:
    BASIC, DIGEST or NONE. Warns once per stanza about a scheme that is not
    answered as asked."""
    if scheme == DIGEST:
        return DIGEST
    if scheme in (NTLM, NEGOTIATE):
        if WARNED.first(stanza, scheme):
            log.warning(
                "site offers %s authentication, which is not supported;"
                " requests are sent without credentials",
                "NTLM" if scheme == NTLM else "Negotiate",
            )
        return NONE
    if scheme != BASIC and WARNED.first(stanza, f"unknown:{scheme}"):
        log.warning(
            "site offers %s authentication, which is not supported;"
            " sending basic credentials, as Website Monitoring did",
            scheme,
        )
    return BASIC


def basic_authorization(creds: Credentials) -> str:
    """The Authorization value for Basic: user and password as Latin-1, as
    requests encoded them, or as UTF-8 when they have characters Latin-1 lacks."""
    pair = f"{creds.username}:{creds.password}"
    try:
        raw = pair.encode("latin-1")
    except UnicodeEncodeError:
        raw = pair.encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class AuthorizationHandler(urllib.request.BaseHandler):
    """Adds one Authorization value to every request of a check that goes to the
    host of the checked URL, redirects included; never to another host, like
    requests, which dropped the header when a redirect left the host.

    It runs after the cookie handler, so Authorization goes out after Cookie, as
    in Website Monitoring's requests.
    """

    handler_order = 550
    """After HTTPCookieProcessor (500)."""

    def __init__(self, url: str, authorization: str) -> None:
        self.host: str | None = urlsplit(url).hostname
        self.authorization: str = authorization

    def http_request(self, req: urllib.request.Request) -> urllib.request.Request:
        if urlsplit(req.full_url).hostname == self.host:
            req.add_unredirected_header("Authorization", self.authorization)
        return req

    https_request = http_request


class DigestError(ValueError):
    """A Digest challenge that cannot be answered. The message says why and
    never contains a credential."""


@dataclass(frozen=True)
class DigestChallenge:
    realm: str
    nonce: str
    algorithm: str | None
    """As the site wrote it; None when it named none (then MD5)."""
    qop_auth: bool
    """The site offers qop=auth; False when it named no qop."""
    opaque: str | None


def digest_challenge(offered: Sequence[str]) -> DigestChallenge | None:
    """The first Digest challenge among the WWW-Authenticate headers, or None.
    Raises DigestError when it cannot be answered: no realm or nonce, an
    algorithm other than MD5, MD5-sess, SHA and SHA-256, a qop list without
    auth (auth-int alone), or MD5-sess without qop."""
    for value in offered:
        scheme, _, rest = value.strip().partition(" ")
        if scheme.lower() != DIGEST:
            continue
        fields = {
            key.lower(): item
            for key, item in parse_keqv_list(parse_http_list(rest)).items()
        }
        realm, nonce = fields.get("realm"), fields.get("nonce")
        if realm is None or nonce is None:
            raise DigestError("challenge without realm or nonce")
        algorithm = fields.get("algorithm")
        if (algorithm or "MD5").upper() not in DIGEST_HASHES:
            raise DigestError(f"algorithm {algorithm} is not supported")
        qop = fields.get("qop")
        offered_qop = [] if qop is None else [q.strip().lower() for q in qop.split(",")]
        if offered_qop and "auth" not in offered_qop:
            raise DigestError(f"qop {qop} is not supported")
        if not offered_qop and (algorithm or "").upper() == "MD5-SESS":
            # Its hash needs a cnonce, which a response without qop cannot carry.
            raise DigestError("algorithm MD5-sess without qop is not supported")
        return DigestChallenge(
            realm=realm,
            nonce=nonce,
            algorithm=algorithm,
            qop_auth=bool(offered_qop),
            opaque=fields.get("opaque"),
        )
    return None


def request_uri(url: str) -> str:
    """The URI a Digest response names: path and query of the request, as
    requests wrote it."""
    parts = urlsplit(url)
    path = parts.path or "/"
    return f"{path}?{parts.query}" if parts.query else path


def _quoted(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def digest_authorization(
    creds: Credentials,
    challenge: DigestChallenge,
    method: str,
    uri: str,
    cnonce: str | None = None,
) -> str:
    """The Authorization value answering challenge for one request (nonce count
    1), field for field as requests built it. The hashes are not used for
    security, so they are also available on FIPS hosts; raises DigestError if
    the host has none for the algorithm."""
    algorithm = (challenge.algorithm or "MD5").upper()
    name = DIGEST_HASHES[algorithm]

    def digest(text: str) -> str:
        try:
            hashed = hashlib.new(name, text.encode("utf-8"), usedforsecurity=False)
        except ValueError:
            raise DigestError(
                f"algorithm {algorithm} is not available on this host"
            ) from None
        return hashed.hexdigest()

    cnonce = cnonce if cnonce is not None else secrets.token_hex(8)
    nc = "00000001"
    ha1 = digest(f"{creds.username}:{challenge.realm}:{creds.password}")
    if algorithm == "MD5-SESS":
        ha1 = digest(f"{ha1}:{challenge.nonce}:{cnonce}")
    ha2 = digest(f"{method}:{uri}")
    if challenge.qop_auth:
        response = digest(f"{ha1}:{challenge.nonce}:{nc}:{cnonce}:auth:{ha2}")
    else:
        response = digest(f"{ha1}:{challenge.nonce}:{ha2}")
    parts = [
        f"username={_quoted(creds.username)}",
        f"realm={_quoted(challenge.realm)}",
        f"nonce={_quoted(challenge.nonce)}",
        f"uri={_quoted(uri)}",
        f'response="{response}"',
    ]
    if challenge.opaque is not None:
        parts.append(f"opaque={_quoted(challenge.opaque)}")
    if challenge.algorithm is not None:
        parts.append(f"algorithm={_quoted(challenge.algorithm)}")
    if challenge.qop_auth:
        parts.append(f'qop="auth", nc={nc}, cnonce="{cnonce}"')
    return "Digest " + ", ".join(parts)


def digest_answer(
    creds: Credentials, headers: Message, url: str, stanza: str, log: StanzaLogger
) -> str | None:
    """The Authorization value answering the Digest challenge of a 401 to a GET
    of url, or None when there is none to answer. A challenge that cannot be
    answered is warned about once per stanza and reason."""
    try:
        challenge = digest_challenge(challenges(headers))
        if challenge is None:
            log.debug("401 without a Digest challenge, not answered")
            return None
        return digest_authorization(creds, challenge, "GET", request_uri(url))
    except DigestError as exc:
        if WARNED.first(stanza, f"digest:{exc}"):
            log.warning(
                "site's Digest challenge cannot be answered (%s); the check reports the 401",
                exc,
            )
        return None
