"""Response bodies: undo the Content-Encoding within a cap on the decoded size."""

from __future__ import annotations

import zlib
from collections.abc import Sequence

MAX_BODY_BYTES = 50 * 1024 * 1024
"""Decoded bytes kept per check; one process serves every stanza, so the memory a
single site can take must stay bounded, compression bombs included."""
DECODE_STEP = 64 * 1024
"""The most output one decompress call may produce."""
_GZIP_WBITS = 16 + zlib.MAX_WBITS
_CODINGS = {"gzip": "gzip", "x-gzip": "gzip", "deflate": "deflate"}


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


def encoding_of(values: Sequence[str] | None) -> str | None:
    """All Content-Encoding header lines as one value, as requests merged them."""
    return ", ".join(values) if values else None
