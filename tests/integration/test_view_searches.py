"""Every search of the app's views runs on website-ping's events.

Runs on the parity stack: its inputs give the views failures, timeouts, slow
responses and content checks to show. Each search runs as admin in
website_ping's namespace with the default value of every form token, the way
the view runs it when opened. A post-process search runs after its base search.

With --keep the parity stack stays up after the session, and the views can be
opened in Splunk Web on so1's port 8000, published on 127.0.0.1.
"""

from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from wptest import golden
from wptest.install import ROOT
from wptest.stack import Stack
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.parity

APP = "website_ping"
VIEWS = ROOT / "default" / "data" / "ui" / "views"
EVENT_TIMEOUT = 180
WEB_TIMEOUT = 180
TITLES = ("refused", "timeout", "status-503", "status-200", "match-no", "thresholds")
"""Inputs whose first event must be indexed before the searches run."""
NEEDS_ROWS = frozenset({"status_overview", "status_history", "exec_summary"})
"""Views whose every search must return at least one row on the parity data."""
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


def results(stack: Stack, query: str) -> list[dict[str, golden.FieldValue]]:
    """Final results of the query in the app's namespace; a search error fails."""
    text = stack.rest("so1").export_in_app(
        APP, query if query.startswith("|") else f"search {query}"
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


def first_event(stack: Stack, title: str) -> list[dict[str, str]] | None:
    rows = stack.searcher("so1").search(
        f"search index=main sourcetype=web_ping title={title}"
        f" _index_earliest={int(stack.mark)} | head 1"
    )
    return rows or None


@pytest.fixture
def stack(parity_stack: Stack) -> Stack:
    """The parity stack once every input in TITLES has a check event."""
    for title in TITLES:
        _ = wait_for(
            INDEXED,
            partial(first_event, parity_stack, title),
            EVENT_TIMEOUT,
            parity_stack.stages,
        )
    return parity_stack


def web_login_page(port: int) -> int | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(
            f"http://127.0.0.1:{port}/en-US/account/login", timeout=30
        ) as response:
            return cast(int, response.status)
    except (urllib.error.URLError, OSError):
        return None


def test_splunk_web_answers(stack: Stack) -> None:
    """Splunk Web serves its login page on the published port. With --keep the
    stack is kept for a look at the views."""
    stack.keep_requested = True
    port = stack.port("so1", 8000)
    status = wait_for(
        "Splunk Web", partial(web_login_page, port), WEB_TIMEOUT, stack.stages
    )
    assert status == 200


@pytest.mark.parametrize("view", VIEW_NAMES)
def test_view_is_registered(stack: Stack, view: str) -> None:
    entry = stack.rest("so1").get(f"/servicesNS/nobody/{APP}/data/ui/views/{view}")
    assert entry.get("entry"), view


@pytest.mark.parametrize("search", SEARCHES, ids=[s.id for s in SEARCHES])
def test_view_search_runs(stack: Stack, search: ViewSearch) -> None:
    rows = results(stack, search.query)
    if search.view in NEEDS_ROWS:
        assert rows, f"{search.id}: no rows"
