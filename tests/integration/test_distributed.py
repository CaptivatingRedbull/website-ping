"""Roles, deployment delivery, the event path and the input lifecycle."""

from __future__ import annotations

import time

import pytest
from wptest import install
from wptest.contract import Scenario, compare, describe
from wptest.evidence import Evidence
from wptest.install import APP, CONFIG_APP, DEPLOYMENT_APPS, Package
from wptest.splunk_rest import events_query
from wptest.stack import SPLUNK, Stack
from wptest.wait import INDEXED, SEARCH_HEAD, wait_for

pytestmark = pytest.mark.distributed

EVENT_TIMEOUT = 120
SETTLE = 60
QUIET_WINDOW = 45
DIST_INPUTS = f"{DEPLOYMENT_APPS}/{CONFIG_APP}/default/inputs.conf"

DIST_CHECK = Scenario(
    "dist-check",
    "http://target:8080/status/200",
    15,
    200,
    0,
    settings={"timeout": "5", "disabled": "0"},
)


def check_event(stack: Stack, service: str, stage: str, evidence: Evidence) -> None:
    searcher = stack.searcher(service)
    events = wait_for(
        stage,
        lambda: searcher.search(events_query(DIST_CHECK.title, stack.mark)) or None,
        EVENT_TIMEOUT,
        stack.stages,
    )
    diffs = compare(
        DIST_CHECK, events, host="hf", mark=stack.mark, searched_at=time.time()
    )
    evidence.note(f"{stack.project}.{service}.dist-check", [str(d) for d in diffs])
    if diffs:
        pytest.fail(describe(DIST_CHECK, diffs), pytrace=False)


def events_since(stack: Stack, since: float) -> list[dict[str, str]]:
    """dist-check events on the indexer whose _time is at or after since."""
    return stack.searcher("idx").search(
        events_query(DIST_CHECK.title, since, extra=f"earliest={int(since)}")
    )


def app_errors_since(stack: Stack, since: float) -> list[dict[str, str]]:
    """ERROR lines about the input in the forwarder's splunkd.log, on the indexer."""
    return stack.searcher("idx").search(
        "search index=_internal host=hf source=*splunkd.log* log_level=ERROR"
        f' "web_ping" earliest={int(since)} | table _time _raw'
    )


def set_disabled(stack: Stack, value: int) -> None:
    stack.exec(
        "ds", f"sed -i 's/^disabled = [01]$/disabled = {value}/' {DIST_INPUTS}\n"
    )
    stack.splunk("ds", "reload deploy-server")


def quiet_window(stack: Stack) -> float:
    """Wait for the change to take effect, then require no new events."""
    time.sleep(SETTLE)
    start = time.time()
    time.sleep(QUIET_WINDOW)
    return start


def test_apps_absent_before_checkin(distributed_stack: Stack) -> None:
    assert distributed_stack.facts["hf_apps_before_checkin"] == []


def test_deployment_server_keeps_script_mode(distributed_stack: Stack) -> None:
    assert distributed_stack.facts["ds_script_mode"] == "755"


def test_forwarder_received_both_apps(
    distributed_stack: Stack, package: Package
) -> None:
    stack = distributed_stack
    assert install.apps_present(stack, "hf") == sorted([APP, CONFIG_APP])
    assert install.verify_install(stack, "hf", package, deployed=True) == []


@pytest.mark.parametrize("service", ["idx", "sh"])
def test_app_installed_without_stanza(
    distributed_stack: Stack, package: Package, service: str
) -> None:
    stack = distributed_stack
    assert install.verify_install(stack, service, package) == []
    output = stack.exec(service, f"{SPLUNK} btool inputs list --debug\n")
    assert "web_ping://" not in output


def test_event_on_indexer(distributed_stack: Stack, evidence: Evidence) -> None:
    check_event(distributed_stack, "idx", INDEXED, evidence)


def test_event_on_search_head(distributed_stack: Stack, evidence: Evidence) -> None:
    check_event(distributed_stack, "sh", SEARCH_HEAD, evidence)


def test_disable_enable_and_outage(distributed_stack: Stack) -> None:
    stack = distributed_stack
    began = time.time()

    set_disabled(stack, 1)
    quiet_from = quiet_window(stack)
    assert events_since(stack, quiet_from) == [], "events while disabled"

    set_disabled(stack, 0)
    enabled_at = time.time()
    wait_for(
        "event after re-enabling",
        lambda: events_since(stack, enabled_at) or None,
        EVENT_TIMEOUT,
        stack.stages,
    )

    stack.splunk("hf", "stop", timeout=install.RESTART_TIMEOUT)
    quiet_from = quiet_window(stack)
    assert events_since(stack, quiet_from) == [], (
        "events while the forwarder was stopped"
    )

    stack.splunk(
        "hf", "start --answer-yes --no-prompt", timeout=install.RESTART_TIMEOUT
    )
    started_at = time.time()
    wait_for(
        "event after starting the forwarder",
        lambda: events_since(stack, started_at) or None,
        EVENT_TIMEOUT,
        stack.stages,
    )
    assert app_errors_since(stack, began) == []
