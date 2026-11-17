from __future__ import annotations

import gzip
import hashlib
import json
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from target import server
from wp_content import (
    DECODE_STEP,
    MAX_BODY_BYTES,
    BodyDecoder,
    ContentDecodingError,
    content_codings,
    encoding_of,
)

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


def test_encoding_of_merges_header_lines() -> None:
    assert encoding_of(None) is None
    assert encoding_of([]) is None
    assert encoding_of(["gzip", "deflate"]) == "gzip, deflate"


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
