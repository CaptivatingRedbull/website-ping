"""website-ping's check events compared with Website Monitoring 2.9.7's golden events.

The parity stack runs the scenarios of wptest/parity.py that website-ping can
already match; the others are skipped with the feature they still need.
"""

from __future__ import annotations

import pytest
from wptest import golden, legacy, parity
from wptest.evidence import Evidence
from wptest.install import ROOT
from wptest.splunk_rest import Searcher
from wptest.stack import Stack
from wptest.wait import INDEXED, STARTED, wait_for

pytestmark = pytest.mark.parity

GOLDEN_DIR = ROOT / "tests" / "golden" / legacy.LEGACY_VERSION
EVENT_TIMEOUT = 180


def _param(scenario: parity.ParityScenario) -> object:
    reason = parity.PENDING.get(scenario.title)
    if scenario.title in parity.REFUSED:
        reason = "refused by website-ping on purpose; see the refused-stanza test"
    marks = [pytest.mark.skip(reason=reason)] if reason else []
    return pytest.param(scenario, id=scenario.title, marks=marks)


def check_rows(
    searcher: Searcher, title: str, since: float
) -> list[dict[str, golden.FieldValue]] | None:
    """The scenario's check events since the mark in arrival order, or None."""
    searcher.search(golden.export_query(since, title))
    rows = [
        row
        for row in golden.parse_export(searcher.last_result)
        if row.get("sourcetype") == golden.CHECK_SOURCETYPE
    ]
    return sorted(rows, key=golden.arrival_order) or None


@pytest.mark.parametrize("scenario", [_param(s) for s in parity.PARITY_SCENARIOS])
def test_check_event_matches_golden(
    parity_stack: Stack, scenario: parity.ParityScenario, evidence: Evidence
) -> None:
    fixture = golden.read_capture(GOLDEN_DIR, scenario.title)
    expected = [e for e in fixture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    assert expected, f"{scenario.title}: the fixture has no check event"
    searcher = parity_stack.searcher("so1")
    rows = wait_for(
        INDEXED,
        lambda: check_rows(searcher, scenario.title, parity_stack.mark),
        EVENT_TIMEOUT,
        parity_stack.stages,
    )
    actual = golden.event_from_result(rows[-1])
    diffs = golden.compare(
        expected[-1], actual, golden.parity_allowed(scenario.title, expected[-1])
    )
    evidence.note(
        f"{parity_stack.project}.parity.{scenario.title}", [str(d) for d in diffs]
    )
    failing = [str(diff) for diff in golden.failing(diffs)]
    # The input sets the event time: a time in the title or URL must not move it.
    event_time = actual.fields.get("_time")
    if event_time != golden.TIME:
        failing.append(f"_time: expected the time of the check, got {event_time}")
    if failing:
        lines = [f"{scenario.title}: {len(failing)} field(s) differ from 2.9.7"]
        lines += [f"  {line}" for line in failing]
        lines += [f"  _raw: {actual.raw}"]
        pytest.fail("\n".join(lines), pytrace=False)


def first_requests(
    stack: Stack, scenario: parity.ParityScenario, count: int
) -> list[golden.TargetRequest] | None:
    """The scenario's first count requests since the mark, or None until logged."""
    sent = [
        golden.target_request(record)
        for record in stack.target_log()
        if scenario.matches_request(
            int(str(record.get("port", 0))), str(record.get("path", ""))
        )
    ]
    return sent[:count] if len(sent) >= count else None


@pytest.mark.parametrize("title", parity.REQUESTS_COMPARED)
def test_requests_match_golden(
    parity_stack: Stack, title: str, evidence: Evidence
) -> None:
    scenario = parity.by_title()[title]
    fixture = golden.read_capture(GOLDEN_DIR, title)
    assert fixture.requests, f"{title}: the fixture has no request"
    sent = wait_for(
        INDEXED,
        lambda: first_requests(parity_stack, scenario, len(fixture.requests)),
        EVENT_TIMEOUT,
        parity_stack.stages,
    )
    diffs = golden.compare_requests(fixture.requests, sent, golden.REQUEST_ALLOWED)
    evidence.note(
        f"{parity_stack.project}.parity-requests.{title}", [str(d) for d in diffs]
    )
    failing = [str(diff) for diff in golden.failing(diffs)]
    if failing:
        lines = [f"{title}: {len(failing)} request field(s) differ from 2.9.7"]
        pytest.fail("\n".join(lines + [f"  {line}" for line in failing]), pytrace=False)


def first_proxy_requests(
    stack: Stack, scenario: parity.ParityScenario, count: int
) -> list[golden.ProxyRequest] | None:
    """The scenario's first count requests through Squid since the mark, or None
    until logged."""
    sent = [
        request
        for logged, request in golden.parse_squid_log(stack.logs("squid"))
        if logged >= stack.mark and scenario.matches_proxy(request.url)
    ]
    return sent[:count] if len(sent) >= count else None


@pytest.mark.parametrize("title", parity.PROXIES_COMPARED)
def test_proxy_requests_match_golden(
    parity_stack: Stack, title: str, evidence: Evidence
) -> None:
    scenario = parity.by_title()[title]
    fixture = golden.read_capture(GOLDEN_DIR, title)
    assert fixture.proxy_requests, f"{title}: the fixture has no proxy request"
    sent = wait_for(
        INDEXED,
        lambda: first_proxy_requests(
            parity_stack, scenario, len(fixture.proxy_requests)
        ),
        EVENT_TIMEOUT,
        parity_stack.stages,
    )
    diffs = golden.compare_requests(
        fixture.proxy_requests, sent, golden.PROXY_REQUEST_ALLOWED
    )
    evidence.note(
        f"{parity_stack.project}.parity-proxy.{title}", [str(d) for d in diffs]
    )
    failing = [str(diff) for diff in golden.failing(diffs)]
    if failing:
        lines = [f"{title}: {len(failing)} proxy request field(s) differ from 2.9.7"]
        pytest.fail("\n".join(lines + [f"  {line}" for line in failing]), pytrace=False)


@pytest.mark.parametrize("title", sorted(parity.REFUSED))
def test_refused_stanza_logs_an_error_and_is_not_run(
    parity_stack: Stack, title: str
) -> None:
    prefix = f"ERROR stanza=web_ping://{title} "
    message = parity.REFUSED[title]
    line = wait_for(
        STARTED,
        lambda: next(
            (
                line
                for _, line in parity_stack.app_log("so1")
                if prefix in line and message in line
            ),
            None,
        ),
        EVENT_TIMEOUT,
        parity_stack.stages,
    )
    assert "not run" in line, line
    searcher = parity_stack.searcher("so1")
    assert check_rows(searcher, title, parity_stack.mark) is None
    assert parity_stack.target_requests(title) == 0
