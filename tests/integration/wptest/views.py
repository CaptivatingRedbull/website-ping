"""The searches of the app's views, as a view runs them when opened, and running
a search in an app's namespace with search errors reported."""

from __future__ import annotations

import html
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from wptest import golden
from wptest.install import ROOT
from wptest.splunk_rest import SplunkRest

APP = "website_ping"
VIEWS = ROOT / "default" / "data" / "ui" / "views"
TOKEN = re.compile(r"\$([^$\s]*)\$")


@dataclass(frozen=True)
class ViewSearch:
    view: str
    name: str
    query: str

    @property
    def id(self) -> str:
        return f"{self.view}:{self.name}"


def token_defaults(root: ET.Element) -> dict[str, str]:
    """The <default> of every form input that sets a token, as written."""
    defaults: dict[str, str] = {}
    for element in root.iter("input"):
        token = element.get("token")
        default = element.find("default")
        if token and default is not None and len(default) == 0:
            defaults[token] = default.text or ""
    return defaults


def apply_filter(value: str, name: str, where: str) -> str:
    """A Simple XML token filter: |s quotes, |u URL-encodes, |h escapes HTML,
    |n leaves the value as it is."""
    if name == "s":
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if name == "u":
        return urllib.parse.quote(value, safe="")
    if name == "h":
        return html.escape(value)
    if name == "n":
        return value
    raise ValueError(f"{where}: unknown token filter |{name}")


def fill_tokens(query: str, tokens: Mapping[str, str], where: str) -> str:
    """Tokens replaced by their defaults, filters applied; $$ is a literal dollar
    sign."""

    def replace(match: re.Match[str]) -> str:
        if not match.group(1):
            return "$"
        name, *filters = match.group(1).split("|")
        if name not in tokens:
            raise ValueError(f"{where}: token ${name}$ has no default value")
        value = tokens[name]
        for filter_name in filters:
            value = apply_filter(value, filter_name, where)
        return value

    return TOKEN.sub(replace, query)


def view_searches(path: Path) -> list[ViewSearch]:
    """Each <search> with a query, a post-process search joined to its base."""
    root = ET.parse(path).getroot()
    tokens = token_defaults(root)
    view = path.stem
    bases: dict[str, str] = {}
    found: list[ViewSearch] = []
    for number, search in enumerate(root.iter("search"), 1):
        element = search.find("query")
        if element is None or not (element.text or "").strip():
            continue
        query = (element.text or "").strip()
        base = search.get("base")
        if base is not None:
            if base not in bases:
                raise ValueError(f"{view}: search {number} names unknown base {base}")
            query = f"{bases[base]}\n{query}"
        search_id = search.get("id")
        if search_id:
            bases[search_id] = query
        name = search_id or f"search{number}"
        found.append(
            ViewSearch(view, name, fill_tokens(query, tokens, f"{view} {name}"))
        )
    return found


SEARCHES = [s for p in sorted(VIEWS.glob("*.xml")) for s in view_searches(p)]
VIEW_NAMES = sorted(p.stem for p in VIEWS.glob("*.xml"))


def results_in_app(
    rest: SplunkRest, query: str, app: str = APP
) -> list[dict[str, golden.FieldValue]]:
    """Final results of the query run as admin in the app's namespace; a search
    error fails the calling test. A query that does not start with a pipe gets
    "search" in front."""
    text = rest.export_in_app(
        app, query if query.startswith(("|", "search ")) else f"search {query}"
    )
    for line in text.splitlines():
        if not line.strip():
            continue
        entry = cast("dict[str, object]", json.loads(line))
        messages = cast("list[dict[str, str]]", entry.get("messages") or [])
        errors = [
            m.get("text", "") for m in messages if m.get("type") in ("ERROR", "FATAL")
        ]
        assert not errors, f"{query}: {errors}"
    return golden.parse_export(text)
