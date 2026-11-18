from __future__ import annotations

import gzip
import hashlib
import json
import zlib
from collections.abc import Iterator, Mapping
from email.message import Message
from pathlib import Path

import pytest
from target import server
from wp_content import (
    DECODE_STEP,
    MAX_BODY_BYTES,
    BodyDecoder,
    ContentDecodingError,
    body_charset,
    content_codings,
    content_hashes,
    decode_body,
    header_fields,
    header_value,
    parse_content_type,
    truncate_body,
)
from wptest import golden

TEXT = ("Grüße aus München. " * 200).encode("utf-8")
GOLDEN_DIR = Path(__file__).parent / "golden" / "2.9.7"


def deflate(data: bytes, raw: bool = False) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS if raw else zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def decode(body: bytes, encoding: str | None, step: int = 0) -> bytes:
    decoder = BodyDecoder(encoding)
    chunks = [body[i : i + step] for i in range(0, len(body), step)] if step else [body]
    for chunk in chunks:
        decoder.feed(chunk)
    decoder.finish()
    assert not decoder.full
    return bytes(decoder.body)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, ()),
        ("", ()),
        ("identity", ()),
        ("gzip", ("gzip",)),
        ("X-GZIP", ("gzip",)),
        (" Deflate ", ("deflate",)),
        ("gzip, deflate", ("deflate", "gzip")),
        ("deflate,identity,gzip", ("gzip", "deflate")),
        ("br", None),
        ("gzip, br", None),
    ],
)
def test_content_codings(header: str | None, expected: tuple[str, ...] | None) -> None:
    assert content_codings(header) == expected


def message(*lines: tuple[str, str]) -> Message:
    headers = Message()
    for name, value in lines:
        headers[name] = value  # adds a line, also for a name already present
    return headers


def test_header_value_merges_header_lines() -> None:
    headers = message(("Content-Encoding", "gzip"), ("content-encoding", "deflate"))
    assert header_value(headers, "Content-Encoding") == "gzip, deflate"
    assert header_value(headers, "CONTENT-ENCODING") == "gzip, deflate"
    assert header_value(headers, "Content-Type") is None


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        (None, TEXT),
        ("gzip", gzip.compress(TEXT)),
        ("x-gzip", gzip.compress(TEXT)),
        ("deflate", deflate(TEXT)),
        ("deflate", deflate(TEXT, raw=True)),
        ("gzip, deflate", deflate(gzip.compress(TEXT))),
        ("deflate, gzip", gzip.compress(deflate(TEXT, raw=True))),
        ("identity", TEXT),
    ],
    ids=["none", "gzip", "x-gzip", "zlib", "raw", "gzip-deflate", "raw-gzip", "id"],
)
@pytest.mark.parametrize("step", [0, 1, 7, 4096])
def test_decodes(encoding: str | None, body: bytes, step: int) -> None:
    assert decode(body, encoding, step) == TEXT


def test_unknown_coding_keeps_the_body_as_received() -> None:
    body = b"\x8b\x00not brotli at all"
    assert decode(body, "br") == body


def test_empty_body_with_a_coding_is_empty() -> None:
    assert decode(b"", "gzip") == b""


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        ("gzip", gzip.compress(TEXT)[:-12]),
        ("deflate", deflate(TEXT)[:-12]),
        ("deflate", deflate(TEXT, raw=True)[:-12]),
        ("gzip, deflate", deflate(gzip.compress(TEXT)[:-12])),
    ],
    ids=["gzip", "zlib", "raw", "inner-gzip"],
)
def test_truncated_stream_is_an_error(encoding: str, body: bytes) -> None:
    with pytest.raises(ContentDecodingError, match="ends before"):
        _ = decode(body, encoding)


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        ("gzip", b"\x1f\x8b\x08\x00garbage-garbage-garbage"),
        ("gzip", TEXT),
        ("deflate", b"\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_data_that_does_not_decode_is_an_error(encoding: str, body: bytes) -> None:
    with pytest.raises(ContentDecodingError, match=f"cannot decode the {encoding}"):
        _ = decode(body, encoding)


def test_trailing_bytes_after_the_stream_are_ignored() -> None:
    assert decode(gzip.compress(TEXT) + b"junk", "gzip") == TEXT


@pytest.fixture(scope="module")
def bomb() -> bytes:
    """1 GiB of zeros, gzip-compressed to about 1 MB."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    block = bytes(1 << 20)
    parts = [compressor.compress(block) for _ in range(1024)]
    return b"".join(parts) + compressor.flush()


def chunks(data: bytes, size: int) -> Iterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def test_bomb_stops_at_the_cap(bomb: bytes) -> None:
    decoder = BodyDecoder("gzip")
    fed = 0
    for chunk in chunks(bomb, 64 * 1024):
        decoder.feed(chunk)
        fed += len(chunk)
        if decoder.full:
            break
    assert decoder.full
    assert len(decoder.body) == MAX_BODY_BYTES
    assert fed < len(bomb)


def test_body_of_exactly_the_cap_is_complete() -> None:
    data = b"x" * (3 * DECODE_STEP)
    decoder = BodyDecoder("gzip", limit=len(data))
    decoder.feed(gzip.compress(data))
    decoder.finish()
    assert not decoder.full
    assert bytes(decoder.body) == data


def test_cap_counts_decoded_bytes() -> None:
    decoder = BodyDecoder("gzip", limit=1000)
    decoder.feed(gzip.compress(TEXT))
    assert decoder.full
    assert bytes(decoder.body) == TEXT[:1000]
    decoder.finish()  # no error for a stream left unfinished at the cap


@pytest.mark.parametrize("title", ["gzip", "gzip-forced", "deflate", "deflate-raw"])
def test_target_bodies_decode_to_the_fixture_hashes(title: str) -> None:
    """The target's encoded bodies decode to the text 2.9.7 hashed."""
    if title.startswith("gzip"):
        encoded, coding = server.gzip_body(server.ENCODED_BODY), "gzip"
    else:
        raw = title == "deflate-raw"
        encoded, coding = server.deflate_body(server.ENCODED_BODY, raw=raw), "deflate"
    text = decode(encoded, coding, step=5).decode("utf-8")
    fixture = json.loads((GOLDEN_DIR / f"{title}.json").read_text(encoding="utf-8"))
    fields = fixture["events"][0]["fields"]
    assert hashlib.md5(text.encode("utf-8")).hexdigest() == fields["content_md5"]
    assert len(text) == int(fields["content_size"])


# ---- headers -------------------------------------------------------------------


def test_header_fields_keep_order_and_first_spelling_and_merge_repeats() -> None:
    headers = message(
        ("Server", "wptest"),
        ("Set-Cookie", "a=1"),
        ("X-Wptest", "one"),
        ("set-cookie", "b=2"),
    )
    assert header_fields(headers) == (
        ("Server", "wptest"),
        ("Set-Cookie", "a=1, b=2"),
        ("X-Wptest", "one"),
    )


def test_header_fields_of_no_headers() -> None:
    assert header_fields(Message()) == ()


# ---- charset and decoding ------------------------------------------------------


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        (None, None),
        ("", None),
        ("text/html", "ISO-8859-1"),
        ("text/plain;format=flowed", "ISO-8859-1"),
        ("application/xhtml+text", "ISO-8859-1"),
        ("TEXT/HTML", None),
        ("application/json", None),
        ("application/octet-stream", None),
        ("text/html; charset=utf-8", "utf-8"),
        ('text/html; Charset="UTF-8"', "UTF-8"),
        ("application/json; charset='latin1'", "latin1"),
        ('text/plain; name="a;b"; charset=koi8-r', "koi8-r"),
        ("text/plain; charset=utf-8; charset=cp1252", "cp1252"),
        ("text/plain; charset=", ""),
    ],
)
def test_body_charset_follows_requests(
    content_type: str | None, expected: str | None
) -> None:
    assert body_charset(content_type) == expected


def test_parse_content_type_unquotes_and_lowercases_names() -> None:
    assert parse_content_type('Text/HTML ; CharSet="a\\"b" ; x') == (
        "Text/HTML",
        {"charset": 'a"b'},
    )


@pytest.mark.parametrize(
    ("raw", "content_type", "expected"),
    [
        (b"", "text/html; charset=utf-16", ""),
        ("Grüße".encode(), "text/html; charset=utf-8", "Grüße"),
        ("Grüße".encode("latin-1"), "text/html", "Grüße"),
        ("Grüße".encode(), "text/html", "Gr\u00c3\u00bc\u00c3\u009fe"),
        ("Grüße".encode(), "application/json", "Grüße"),
        ("Grüße".encode(), None, "Grüße"),
        ("Grüße".encode("latin-1"), None, "Gr\ufffd\ufffde"),
        ("Grüße".encode(), "text/html; charset=no-such-codec", "Grüße"),
        ("Grüße".encode(), "text/html; charset=", "Grüße"),
        ("Grüße".encode(), "text/html; charset=hex", "Grüße"),
        ("Grüße".encode(), "text/html; charset=idna", "Grüße"),
        (b"a\xffb", "text/plain; charset=utf-8", "a\ufffdb"),
    ],
    ids=[
        "empty",
        "utf-8",
        "text-without-charset-is-latin-1",
        "utf-8-read-as-latin-1",
        "json-without-charset",
        "no-content-type",
        "latin-1-without-content-type",
        "unknown-codec",
        "empty-charset",
        "not-a-text-codec",
        "codec-without-replace",
        "bad-bytes-replaced",
    ],
)
def test_decode_body(raw: bytes, content_type: str | None, expected: str) -> None:
    assert decode_body(raw, content_type) == expected


def test_decode_body_takes_a_bytearray() -> None:
    assert decode_body(bytearray(b"ok"), None) == "ok"


# ---- hashes, compared with the fixtures ------------------------------------------


def check_fields(title: str) -> Mapping[str, golden.FieldValue]:
    capture = golden.read_capture(GOLDEN_DIR, title)
    checks = [e for e in capture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    return checks[-1].fields


def hashed(text: str) -> tuple[str, str, str]:
    hashes = content_hashes(text)
    return hashes.md5, hashes.sha224, str(hashes.size)


def fixture_hashes(fields: Mapping[str, golden.FieldValue]) -> tuple[str, ...]:
    return tuple(
        str(fields[name]) for name in ("content_md5", "content_sha224", "content_size")
    )


@pytest.mark.parametrize("case", sorted(server.CONTENT_CASES))
def test_content_cases_hash_like_the_fixtures(case: str) -> None:
    """Hashes and size of every target content case equal 2.9.7's, except
    where the fixture allows a difference."""
    title = f"content-{case}"
    content_type, raw = server.CONTENT_CASES[case]
    fields = check_fields(title)
    allowed = golden.allowed_fields(title)
    names = ("content_md5", "content_sha224", "content_size")
    for name, got, want in zip(
        names, hashed(decode_body(raw, content_type)), fixture_hashes(fields)
    ):
        if name not in allowed:
            assert got == want, name


def test_binary_body_differs_only_by_the_guessed_charset() -> None:
    """2.9.7 had chardet guess a charset for application/octet-stream; for the
    bytes 0-255 it chose Windows-1253. website-ping decodes them as UTF-8."""
    content_type, raw = server.CONTENT_CASES["binary"]
    fields = check_fields("content-binary")
    assert hashed(raw.decode("cp1253", errors="replace")) == fixture_hashes(fields)
    assert hashed(decode_body(raw, content_type)) != fixture_hashes(fields)
    assert {"content_md5", "content_sha224"} <= set(
        golden.allowed_fields("content-binary")
    )
    assert "content_size" not in golden.allowed_fields("content-binary")


@pytest.mark.parametrize(
    ("title", "raw"),
    [("body-lines", server.BODY_LINES), ("body-binary", server.BODY_BINARY)],
)
def test_text_bodies_hash_like_the_fixtures(title: str, raw: bytes) -> None:
    text = decode_body(raw, "text/plain; charset=utf-8")
    assert hashed(text) == fixture_hashes(check_fields(title))


def test_hashes_of_the_utf8_text_and_size_in_characters() -> None:
    hashes = content_hashes("Grüße")
    data = "Grüße".encode()
    assert hashes.md5 == hashlib.md5(data).hexdigest()
    assert hashes.sha224 == hashlib.sha224(data).hexdigest()
    assert hashes.size == 5


def test_hashes_accept_lone_surrogates() -> None:
    text = decode_body(b"a\\ud800b", "text/plain; charset=unicode_escape")
    assert text == "a\ud800b"
    assert content_hashes(text).size == 3


def test_md5_is_requested_as_not_for_security(monkeypatch: pytest.MonkeyPatch) -> None:
    """FIPS hosts refuse md5 unless it is marked as not used for security."""
    calls: list[object] = []
    real = hashlib.md5

    def md5(data: bytes = b"", **kwargs: bool) -> object:
        calls.append(kwargs)
        return real(data, **kwargs)

    monkeypatch.setattr(hashlib, "md5", md5)
    _ = content_hashes("ok")
    assert calls == [{"usedforsecurity": False}]


# ---- body event text -------------------------------------------------------------


@pytest.mark.parametrize(
    ("limit", "expected"),
    [
        (-1, "0123456789"),
        (0, None),
        (4, "0123"),
        (10, "0123456789"),
        (99, "0123456789"),
    ],
)
def test_truncate_body(limit: int, expected: str | None) -> None:
    assert truncate_body("0123456789", limit) == expected


def test_truncate_body_counts_characters() -> None:
    assert truncate_body("Grüße", 3) == "Grü"
