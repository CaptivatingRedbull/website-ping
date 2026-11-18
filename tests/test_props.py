"""default/props.conf sets only what the events need."""

from __future__ import annotations

import configparser
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent


def test_props_set_the_event_time_and_nothing_else() -> None:
    """Splunk reads a date from the text of unbroken events even when the input
    writes <time>; DATETIME_CONFIG = NONE stops that for check and body events.
    No other setting: line breaking and search-time extraction stay as in
    Website Monitoring."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    _ = parser.read(ROOT / "default" / "props.conf", encoding="utf-8")
    assert {name: dict(parser[name]) for name in parser.sections()} == {
        "web_ping": {"DATETIME_CONFIG": "NONE"},
        "web_ping:response": {"DATETIME_CONFIG": "NONE"},
        "source::...website_ping.log*": {"sourcetype": "website_ping:log"},
    }
