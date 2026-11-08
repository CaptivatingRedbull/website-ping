from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest
from ping_events import format_event, write_event


def test_format_event() -> None:
    xml = format_event(
        {
            "title": "my site",
            "url": "https://a.de/?x=1&y=2",
            "response_code": 200,
            "timed_out": False,
        },
        timestamp=1700000000.5,
    )
    assert xml == (
        "<stream><event><time>1700000000.500</time><data>"
        'title="my site" url="https://a.de/?x=1&amp;y=2" response_code=200 timed_out=0'
        "</data></event></stream>"
    )


def test_output_is_well_formed_xml_with_odd_values() -> None:
    xml = format_event({"error": 'bad "quote"\nnew line <tag> & more'}, timestamp=1.0)
    data = ET.fromstring(xml).find("event/data")
    assert data is not None
    assert data.text == "error=\"bad 'quote' new line <tag> & more\""


def test_write_event_flushes_one_line(capsys: pytest.CaptureFixture[str]) -> None:
    write_event({"a": 1}, timestamp=1.0)
    out = capsys.readouterr().out
    assert out.endswith("</stream>\n") and out.count("\n") == 1
