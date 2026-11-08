from __future__ import annotations

import sys
import time
from collections.abc import Mapping
from typing import TextIO, Union
from xml.sax.saxutils import escape

FieldValue = Union[str, int, float, bool]


def format_value(value: FieldValue) -> str:
    """Numbers are writte bare, everything else is quoted."""
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, (int, float)):
        return str(value)
    text = " ".join(value.split())
    return '"' + text.replace('"', "'") + '"'


def format_event(
    fields: Mapping[str, FieldValue], timestamp: float | None = None
) -> str:
    """Build the XML splunkd expects for one event."""
    ts = time.time() if timestamp is None else timestamp
    data = " ".join(f"{key}={format_value(value)}" for key, value in fields.items())
    return f"<stream><event><time>{ts:.3f}</time><data>{escape(data)}</data></event></stream>"


def write_event(
    fields: Mapping[str, FieldValue],
    timestamp: float | None = None,
    out: TextIO | None = None,
) -> None:
    stream: TextIO = out or sys.stdout
    _ = stream.write(format_event(fields, timestamp) + "\n")
    stream.flush()
