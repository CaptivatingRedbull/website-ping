from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from ping_events import (
    Field,
    FieldValue,
    escape_value,
    format_data,
    format_event,
    write_event,
    xml_safe,
)
from wptest import golden

GOLDEN_DIR = Path(__file__).parent / "golden" / "2.9.7"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("plain", "plain"),
        ("a b", '"a b"'),
        ("", '""'),
        ('He said "hi" it\'s', '"He said \\"hi\\" it\\\'s"'),
        ('no"space', 'no\\"space'),
        ("tab\tonly", "tab\tonly"),
        ("back\\slash", "back\\slash"),
        ("a=1, b=2", '"a=1, b=2"'),
        (True, "True"),
        (False, "False"),
        (12.5, "12.5"),
        (100.0, "100.0"),
        (0, "0"),
    ],
)
def test_escape_value(value: FieldValue, expected: str) -> None:
    assert escape_value(value) == expected


def test_format_data_keeps_order_and_escapes_keys() -> None:
    fields: list[Field] = [
        ("response_code", ""),
        ("timed_out", True),
        ("title", "my site"),
        ("odd key", 1),
    ]
    assert format_data(fields) == (
        'response_code="" timed_out=True title="my site" "odd key"=1'
    )
    assert format_data([]) == ""


FORBIDDEN = (0x00, 0x08, 0x0B, 0x0C, 0x0E, 0x1F, 0xD800, 0xDFFF, 0xFFFE, 0xFFFF)
ALLOWED = (0x09, 0x0A, 0x0D, 0x20, 0x7F, 0xFC, 0xE000, 0xFFFD, 0x1F600)


@pytest.mark.parametrize("code", FORBIDDEN, ids=[f"U+{c:04X}" for c in FORBIDDEN])
def test_xml_safe_removes_forbidden_characters(code: int) -> None:
    assert xml_safe(f"a{chr(code)}b") == "ab"


def test_xml_safe_keeps_allowed_characters() -> None:
    text = "".join(f"a{chr(code)}" for code in ALLOWED)
    assert xml_safe(text) == text


def test_format_event_layout() -> None:
    event = format_event(
        "web_ping://site",
        'title="a & <b>"',
        time=1700000000.5,
        sourcetype="web_ping",
        source="web_ping://site",
        index="main",
        host="web01",
    )
    assert event == (
        '<stream><event unbroken="1" stanza="web_ping://site">'
        '<data>title="a &amp; &lt;b&gt;"</data><time>1700000000.500</time>'
        "<index>main</index><sourcetype>web_ping</sourcetype>"
        "<source>web_ping://site</source><host>web01</host>"
        "<done/></event></stream>"
    )


@pytest.mark.parametrize("host", [None, "$decideOnStartup"])
def test_format_event_omits_unset_host_and_index(host: str | None) -> None:
    event = format_event(
        "web_ping://s", "a=1", time=1.0, sourcetype="web_ping", source="s", host=host
    )
    assert "<host>" not in event and "<index>" not in event
    assert "<time>1.000</time>" in event


def test_format_event_is_well_formed_with_odd_text() -> None:
    data = 'x="<tag> & \\"q\\"" nul\x00 vt\x0b end'
    event = format_event(
        'web_ping://a "b"', data, time=2.0, sourcetype="web_ping", source="s"
    )
    root = ET.fromstring(event)
    assert root.tag == "stream"
    node = root.find("event")
    assert node is not None
    assert node.get("stanza") == 'web_ping://a "b"'
    assert node.get("unbroken") == "1"
    assert node.findtext("data") == 'x="<tag> & \\"q\\"" nul vt end'
    assert node.find("done") is not None


def test_write_event_writes_and_flushes() -> None:
    out = io.StringIO()
    write_event("<stream></stream>", out)
    assert out.getvalue() == "<stream></stream>"


# ---- Golden fixtures ---------------------------------------------------------


def _value(pair: golden.RawPair) -> str:
    """The value 2.9.7 had before escape_spaces, recovered from _raw.

    A normalised placeholder stands for a captured value; a sample of the same
    shape (a number, a header value with or without a space) normalises back."""
    inner = pair.literal[1:-1] if pair.quoted else pair.literal
    if inner == golden.NUMBER:
        return "12.34"
    if inner == golden.VOLATILE:
        return "volatile value" if pair.quoted else "volatile"
    return inner.replace('\\"', '"').replace("\\'", "'")


def _check_events() -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    for path in sorted(GOLDEN_DIR.glob("*.json")):
        if path.name.startswith("_"):
            continue
        capture = golden.read_capture(GOLDEN_DIR, path.stem)
        for index, event in enumerate(capture.events):
            if event.sourcetype == golden.CHECK_SOURCETYPE:
                events.append((f"{path.stem}[{index}]", event.raw))
    return events


CHECK_EVENTS = _check_events()


def test_every_fixture_is_covered() -> None:
    assert len(CHECK_EVENTS) >= 60


@pytest.mark.parametrize(
    ("name", "raw"), CHECK_EVENTS, ids=[n for n, _ in CHECK_EVENTS]
)
def test_rebuilds_fixture_raw(name: str, raw: str) -> None:
    fields: list[Field] = [(p.key, _value(p)) for p in golden.parse_raw(raw)]
    rebuilt = golden.normalise_raw(format_data(fields), golden.CHECK_SOURCETYPE)
    assert rebuilt == raw, name


def test_fixture_body_without_control_characters_passes_unchanged() -> None:
    capture = golden.read_capture(GOLDEN_DIR, "body-lines")
    bodies = [
        e.raw for e in capture.events if e.sourcetype == golden.RESPONSE_SOURCETYPE
    ]
    assert len(bodies) == 1
    assert xml_safe(bodies[0]) == bodies[0]
