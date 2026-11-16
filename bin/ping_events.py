"""Events in the XML stream format Website Monitoring 2.9.7 wrote.

The text of a check event is key=value pairs quoted the way 2.9.7's
escape_spaces did it, so existing searches and Splunk's automatic field
extraction see the same values.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from typing import TextIO, Union
from xml.sax.saxutils import escape

FieldValue = Union[str, int, float, bool]
Field = tuple[str, FieldValue]

UNSET_HOST = "$decideOnStartup"
"""splunkd passes this literal as the host parameter when inputs.conf sets none."""

# Characters XML 1.0 does not allow. A surrogate code point in a Python string is
# always unpaired (astral characters are one code point) and cannot be encoded.
_XML_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
_ATTRIBUTE_ENTITIES = {'"': "&quot;", "\t": "&#9;", "\n": "&#10;", "\r": "&#13;"}


def xml_safe(text: str) -> str:
    """Remove the characters XML 1.0 forbids; one of them would end the stream."""
    return _XML_FORBIDDEN.sub("", text)


def escape_value(value: FieldValue) -> str:
    """Quote a key or value like 2.9.7: escape both quote characters with a
    backslash, and wrap the result in double quotes if it is empty or contains a
    space. Backslashes are left alone, as 2.9.7 did."""
    text = str(value).replace('"', '\\"').replace("'", "\\'")
    if text == "" or " " in text:
        return f'"{text}"'
    return text


def format_data(fields: Sequence[Field]) -> str:
    """The event text: key=value pairs in the given order, one space apart."""
    return " ".join(
        f"{escape_value(key)}={escape_value(value)}" for key, value in fields
    )


def _element(name: str, text: str) -> str:
    return f"<{name}>{escape(xml_safe(text))}</{name}>"


def format_event(
    stanza: str,
    data: str,
    *,
    time: float,
    sourcetype: str,
    source: str,
    index: str | None = None,
    host: str | None = None,
) -> str:
    """One complete <stream> with one event, laid out as 2.9.7 wrote it, plus <time>.

    time is epoch seconds. index is omitted when None, host when None or the unset
    placeholder, so splunkd fills in its defaults.
    """
    attribute = escape(xml_safe(stanza), _ATTRIBUTE_ENTITIES)
    parts = [
        f'<stream><event unbroken="1" stanza="{attribute}">',
        _element("data", data),
        f"<time>{time:.3f}</time>",
    ]
    if index is not None:
        parts.append(_element("index", index))
    parts.append(_element("sourcetype", sourcetype))
    parts.append(_element("source", source))
    if host is not None and host != UNSET_HOST:
        parts.append(_element("host", host))
    parts.append("<done/></event></stream>")
    return "".join(parts)


def write_event(event: str, out: TextIO | None = None) -> None:
    """Write one formatted event and flush, so splunkd receives it at once."""
    stream: TextIO = out or sys.stdout
    _ = stream.write(event)
    stream.flush()
