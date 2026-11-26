"""default/props.conf sets only what the events and the log lines need."""

from __future__ import annotations

import configparser
import logging
import re
from pathlib import Path

import pytest
from logger import FileFormatter

ROOT = Path(__file__).absolute().parent.parent
LOG_SOURCETYPE = "website_ping:log"


def read_props() -> dict[str, dict[str, str]]:
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    _ = parser.read(ROOT / "default" / "props.conf", encoding="utf-8")
    return {name: dict(parser[name]) for name in parser.sections()}


def test_props_set_the_event_time_and_the_log_fields_and_nothing_else() -> None:
    """Splunk reads a date from the text of unbroken events even when the input
    writes <time>; DATETIME_CONFIG = NONE stops that for check and body events.
    It is bound to the source of the app's own inputs, so the sourcetypes
    web_ping and web_ping:response get no props and data of other apps is not
    affected. Line breaking and search-time extraction of events stay as in
    Website Monitoring. The log file gets one sourcetype and its search-time
    fields."""
    props = read_props()
    assert set(props) == {
        "source::web_ping://...",
        "source::...website_ping.log*",
        LOG_SOURCETYPE,
    }
    assert props["source::web_ping://..."] == {"DATETIME_CONFIG": "NONE"}
    assert props["source::...website_ping.log*"] == {"sourcetype": LOG_SOURCETYPE}
    assert set(props[LOG_SOURCETYPE]) == {"KV_MODE", "EXTRACT-line", "EVAL-stanza"}
    assert props[LOG_SOURCETYPE]["KV_MODE"] == "none"
    assert props[LOG_SOURCETYPE]["EVAL-stanza"] == (
        'coalesce(stanza_plain, replace(stanza_quoted, "\\\\\\\\(.)", "\\1"), "(process)")'
    )


def line_pattern() -> re.Pattern[str]:
    """EXTRACT-line as a Python pattern: PCRE's (?<name>) is (?P<name>) here."""
    extract = read_props()[LOG_SOURCETYPE]["EXTRACT-line"]
    return re.compile(extract.replace("(?<", "(?P<"))


def stanza_of(match: re.Match[str]) -> str:
    """What EVAL-stanza computes: the plain name, else the quoted one with each
    backslash escape removed, else "(process)"."""
    if match["stanza_plain"] is not None:
        return match["stanza_plain"]
    if match["stanza_quoted"] is not None:
        return re.sub(r"\\(.)", r"\1", match["stanza_quoted"])
    return "(process)"


def log_line(level: int, message: str, stanza: str | None) -> str:
    record = logging.LogRecord("web_ping", level, __file__, 1, message, None, None)
    if stanza is not None:
        record.stanza = stanza
    return FileFormatter().format(record)


@pytest.mark.parametrize(
    ("level", "stanza", "message"),
    [
        (logging.WARNING, "web_ping://blank-31", "check failed: redirect limit"),
        (logging.INFO, "web_ping://thresholds", "check done code=200 time=0.303"),
        (logging.DEBUG, "web_ping://my site", "route to target:8080: direct"),
        (logging.ERROR, 'web_ping://He said "hi" \\', "invalid configuration"),
        (logging.INFO, "web_ping://a\\b", "starting check url=http://a/"),
        (logging.INFO, None, "heartbeat stanzas=3 in_flight=0 queued=0"),
        (logging.ERROR, None, 'stanza=web_ping://x v=9 inside "the" message'),
    ],
)
def test_extraction_reads_every_line_the_logger_writes(
    level: int, stanza: str | None, message: str
) -> None:
    line = log_line(level, message, stanza)
    match = line_pattern().match(line)
    assert match is not None, line
    assert match["level"] == logging.getLevelName(level)
    assert stanza_of(match) == (stanza if stanza is not None else "(process)")
    assert match["version"]
    assert match["message"] == message
