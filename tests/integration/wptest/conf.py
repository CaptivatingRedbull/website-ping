"""Reading Splunk .conf files the way the app's tests need them."""

from __future__ import annotations

from pathlib import Path

Conf = dict[str, dict[str, str]]


def parse_conf(text: str) -> Conf:
    """Stanzas of a Splunk .conf text: comments and blank lines skipped, settings
    before the first stanza under "default", a line ending in a backslash
    continued on the next line (the backslash is dropped, the line break kept)."""
    stanzas: Conf = {}
    current = stanzas.setdefault("default", {})
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        while line.endswith("\\") and index < len(lines):
            line = line[:-1] + "\n" + lines[index]
            index += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stanzas.setdefault(stripped[1:-1], {})
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"not a setting: {line!r}")
        current[key.strip()] = value.strip()
    if not stanzas["default"]:
        del stanzas["default"]
    return stanzas


def read_conf(path: Path) -> Conf:
    return parse_conf(path.read_text(encoding="utf-8"))
