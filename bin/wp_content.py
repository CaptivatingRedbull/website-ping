"""Response bodies: undo the Content-Encoding within a cap on the decoded size, then
decode, hash and cut the text as Website Monitoring 2.9.7 (requests) did."""

from __future__ import annotations

import hashlib
import zlib
from dataclasses import dataclass
from email.message import Message

MAX_BODY_BYTES = 50 * 1024 * 1024
"""Decoded bytes kept per check; one process serves every stanza, so the memory a
single site can take must stay bounded, compression bombs included."""
DECODE_STEP = 64 * 1024
"""The most output one decompress call may produce."""
_GZIP_WBITS = 16 + zlib.MAX_WBITS
_CODINGS = {"gzip": "gzip", "x-gzip": "gzip", "deflate": "deflate"}
ISO_8859_1 = "ISO-8859-1"
"""requests' charset for a text type without one (the HTTP/1.1 default, RFC 2616)."""


class ContentDecodingError(ValueError):
    """The body does not decode with its Content-Encoding."""


def content_codings(header: str | None) -> tuple[str, ...] | None:
    """The codings to undo, in the order to undo them (the last applied first).

    Empty for no Content-Encoding or only identity. None when a coding cannot be
    decoded here (such as br): the body is then used as received.
    """
    names = [name.strip().lower() for name in (header or "").split(",")]
    codings: list[str] = []
    for name in names:
        if not name or name == "identity":
            continue
        coding = _CODINGS.get(name)
        if coding is None:
            return None
        codings.append(coding)
    return tuple(reversed(codings))


class _Stage:
    """One coding. deflate is tried with the zlib wrapper first and, when that
    fails before any output, as raw deflate, which some servers send."""

    def __init__(self, coding: str) -> None:
        self.coding: str = coding
        self.fed: bool = False
        self._fallback: bool = coding == "deflate"
        self._held: bytearray = bytearray()
        self._obj = zlib.decompressobj(
            _GZIP_WBITS if coding == "gzip" else zlib.MAX_WBITS
        )

    @property
    def unconsumed_tail(self) -> bytes:
        return self._obj.unconsumed_tail

    @property
    def eof(self) -> bool:
        return self._obj.eof

    def decompress(self, data: bytes, max_length: int) -> bytes:
        self.fed = self.fed or bool(data)
        if self._fallback:
            # Until the first output every byte so far was consumed (output stops
            # early only at max_length), so this is the whole input to replay.
            self._held += data
        try:
            out = self._obj.decompress(data, max_length)
        except zlib.error as exc:
            if not self._fallback:
                raise self._error(exc) from None
            self._fallback = False
            self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
            held, self._held = bytes(self._held), bytearray()
            return self.decompress(held, max_length)
        if out and self._fallback:
            self._fallback = False
            self._held = bytearray()
        return out

    def flush(self) -> bytes:
        try:
            return self._obj.flush()
        except zlib.error as exc:
            raise self._error(exc) from None

    def _error(self, exc: zlib.error) -> ContentDecodingError:
        return ContentDecodingError(f"cannot decode the {self.coding} body: {exc}")


class BodyDecoder:
    """Decode a body chunk by chunk into body, keeping at most limit bytes.

    full is set once the decoded body would exceed limit; the caller then stops
    reading. Raises ContentDecodingError for data that does not decode and, in
    finish, for a compressed stream that ends early.
    """

    def __init__(
        self, content_encoding: str | None, limit: int = MAX_BODY_BYTES
    ) -> None:
        codings = content_codings(content_encoding)
        self._stages: list[_Stage] = [_Stage(c) for c in codings or ()]
        self._limit: int = limit
        self.body: bytearray = bytearray()
        self.full: bool = False

    def feed(self, data: bytes) -> None:
        if data and not self.full:
            self._push(0, data)

    def finish(self) -> None:
        """Flush every coding after the last chunk and check the streams ended."""
        for index, stage in enumerate(self._stages):
            if self.full:
                return
            rest = stage.flush()
            if rest:
                self._push(index + 1, rest)
        if self.full:
            return
        for stage in self._stages:
            if stage.fed and not stage.eof:
                raise ContentDecodingError(
                    f"the body ends before its {stage.coding} stream does"
                )

    def _push(self, index: int, data: bytes) -> None:
        if index == len(self._stages):
            self._keep(data)
            return
        stage = self._stages[index]
        while not self.full:
            out = stage.decompress(data, DECODE_STEP)
            if out:
                self._push(index + 1, out)
            data = stage.unconsumed_tail
            if not data and len(out) < DECODE_STEP:
                return

    def _keep(self, data: bytes) -> None:
        room = self._limit - len(self.body)
        if len(data) > room:
            data = data[:room]
            self.full = True
        self.body += data


def header_value(message: Message, name: str) -> str | None:
    """All lines of one header as one value, joined with ", " as requests merged
    them; None when the header is absent."""
    values = message.get_all(name)
    return ", ".join(str(value) for value in values) if values else None


def header_fields(message: Message) -> tuple[tuple[str, str], ...]:
    """Every response header in the order received, as requests presented them:
    one entry per name (compared without case, spelled as first received) with
    the values of repeated lines joined, such as two Set-Cookie lines as
    "a=1, b=2"."""
    fields: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in message:  # every header line, repeated names included
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        fields.append((name, header_value(message, name) or ""))
    return tuple(fields)


def _split_parameters(value: str) -> list[str]:
    """The parts of a header value between semicolons, ignoring semicolons inside
    quoted strings; the same split as the cgi module's (gone in Python 3.13)."""
    parts: list[str] = []
    rest = ";" + value
    while rest[:1] == ";":
        rest = rest[1:]
        end = rest.find(";")
        while end > 0 and (rest.count('"', 0, end) - rest.count('\\"', 0, end)) % 2:
            end = rest.find(";", end + 1)
        if end < 0:
            end = len(rest)
        parts.append(rest[:end].strip())
        rest = rest[end:]
    return parts


def parse_content_type(value: str) -> tuple[str, dict[str, str]]:
    """The media type and the parameters of a Content-Type value, as requests read
    it: parameter names in lower case, a quoted value unquoted, the last of a
    repeated name wins. The media type keeps its case."""
    media_type, *rest = _split_parameters(value)
    parameters: dict[str, str] = {}
    for part in rest:
        name, equals, text = part.partition("=")
        if not equals:
            continue
        text = text.strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':
            text = text[1:-1].replace("\\\\", "\\").replace('\\"', '"')
        parameters[name.strip().lower()] = text
    return media_type, parameters


def body_charset(content_type: str | None) -> str | None:
    """The charset requests chose from Content-Type: the charset parameter with
    quotes stripped; ISO-8859-1 when the media type contains "text" (checked
    case-sensitively, as requests did); otherwise None."""
    if not content_type:
        return None
    media_type, parameters = parse_content_type(content_type)
    if "charset" in parameters:
        return parameters["charset"].strip("'\"")
    if "text" in media_type:
        return ISO_8859_1
    return None


def decode_body(raw: bytes | bytearray, content_type: str | None) -> str:
    """The body as text, the way Website Monitoring hashed and searched it.

    Decoded with body_charset; with UTF-8 when there is none, when Python has no
    such codec, or when the codec cannot replace bad bytes. Bytes that do not
    decode become U+FFFD. requests guessed a missing charset with chardet; for
    ASCII and UTF-8 bodies UTF-8 gives the same text.
    """
    if not raw:
        return ""
    charset = body_charset(content_type)
    if charset is not None:
        try:
            return raw.decode(charset, errors="replace")
        except (LookupError, ValueError):
            # LookupError: unknown or not a text codec. ValueError (UnicodeError):
            # a codec such as idna that only decodes strictly.
            pass
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class ContentHashes:
    md5: str
    sha224: str
    size: int
    """Characters of the decoded text, not bytes."""


def content_hashes(text: str) -> ContentHashes:
    """Hashes of the UTF-8 encoded text, as 2.9.7 computed them. md5 is a
    fingerprint here, not security, so it is also available on FIPS hosts."""
    # surrogatepass: a codec such as unicode_escape can return lone surrogates,
    # which plain UTF-8 refuses to encode.
    data = text.encode("utf-8", errors="surrogatepass")
    return ContentHashes(
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha224=hashlib.sha224(data).hexdigest(),
        size=len(text),
    )


def truncate_body(text: str, limit: int) -> str | None:
    """The text of the body event for max_response_body_length: the whole body
    for a negative limit, the first limit characters for a positive one, and no
    body event for 0."""
    if limit < 0:
        return text
    if limit == 0:
        return None
    return text[:limit]
