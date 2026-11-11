"""The "no direct route" scenario on an internal-only network, read through exec."""

from __future__ import annotations

import time

import pytest
from wptest.contract import Scenario, compare, describe
from wptest.evidence import Evidence
from wptest.splunk_rest import events_query
from wptest.stack import Stack
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.no_route

EVENT_TIMEOUT = 120

NO_DIRECT_ROUTE = Scenario(
    "no-direct-route",
    "http://192.0.2.10:8080/",
    3600,
    0,
    0,
    "Unreachable network",
    settings={"timeout": "5"},
    max_total_time=7,
)


def test_no_direct_route(no_route_stack: Stack, evidence: Evidence) -> None:
    stack = no_route_stack
    searcher = stack.searcher("so1")
    events = wait_for(
        INDEXED,
        lambda: (
            searcher.search(events_query(NO_DIRECT_ROUTE.title, stack.mark)) or None
        ),
        EVENT_TIMEOUT,
        stack.stages,
    )
    diffs = compare(
        NO_DIRECT_ROUTE,
        events,
        host="so1",
        mark=stack.mark,
        searched_at=time.time(),
    )
    evidence.note(
        f"{stack.project}.scenario.{NO_DIRECT_ROUTE.title}", [str(d) for d in diffs]
    )
    if diffs:
        pytest.fail(describe(NO_DIRECT_ROUTE, diffs), pytrace=False)
