"""Every search of the app's views runs on website-ping's events.

Runs on the parity stack: its inputs give the views failures, timeouts, slow
responses and content checks to show. Each search runs as admin in
website_ping's namespace with the default value of every form token, the way
the view runs it when opened. A post-process search runs after its base search.

With --keep the parity stack stays up after the session, and the views can be
opened in Splunk Web on so1's port 8000, published on 127.0.0.1.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from functools import partial
from typing import cast

import pytest
from wptest import golden
from wptest.stack import Stack
from wptest.views import SEARCHES, VIEW_NAMES, ViewSearch, results_in_app
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.parity

APP = "website_ping"
EVENT_TIMEOUT = 180
WEB_TIMEOUT = 180
TITLES = ("refused", "timeout", "status-503", "status-200", "match-no", "thresholds")
"""Inputs whose first event must be indexed before the searches run."""
NEEDS_ROWS = frozenset({"status_overview", "status_history", "exec_summary"})
"""Views whose every search must return at least one row on the parity data."""


def results(stack: Stack, query: str) -> list[dict[str, golden.FieldValue]]:
    """Final results of the query in the app's namespace; a search error fails."""
    return results_in_app(stack.rest("so1"), query, APP)


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
