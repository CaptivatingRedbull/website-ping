"""Every row of the scenario table, on the standalone stack."""

from __future__ import annotations

import configparser
import time

import pytest
from wptest.contract import Scenario, compare, describe
from wptest.evidence import Evidence
from wptest.install import APPS_DIR
from wptest.splunk_rest import events_query
from wptest.stack import Stack
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.network

EVENT_TIMEOUT = 120
PROXY = "http://squid:3128"
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
QUIET_WINDOW = 45
T = "http://target:8080"

SCENARIOS = [
    Scenario("status-200", f"{T}/status/200", 15, 200, 0),
    Scenario("status-404", f"{T}/status/404", 15, 404, 0),
    Scenario("status-503", f"{T}/status/503", 15, 503, 0),
    Scenario("chain-at-3", f"{T}/chain/chain-at-3/3", 3600, 200, 0,
             settings={"max_redirects": "3"}, requests=4),
    Scenario("chain-at-10", f"{T}/chain/chain-at-10/10", 3600, 200, 0, requests=11),
    Scenario("chain-at-50", f"{T}/chain/chain-at-50/50", 3600, 200, 0,
             settings={"max_redirects": "50"}, requests=51),
    Scenario("repeat-8", f"{T}/repeat/repeat-8/8", 3600, 200, 0,
             settings={"max_redirects": "10"}, requests=9),
    *[
        Scenario(f"redirect-{status}", f"{T}/redirect/{status}/redirect-{status}",
                 3600, 200, 0, requests=2)
        for status in (301, 302, 303, 307, 308)
    ],
    Scenario("over-3", f"{T}/chain/over-3/4", 3600, 302, 0, "Redirect limit",
             settings={"max_redirects": "3"}, requests=4),
    Scenario("over-10", f"{T}/chain/over-10/11", 3600, 302, 0, "Redirect limit", requests=11),
    Scenario("over-50", f"{T}/chain/over-50/51", 3600, 302, 0, "Redirect limit",
             settings={"max_redirects": "50"}, requests=51),
    Scenario("loop", f"{T}/loop/loop", 3600, 302, 0, "Redirect limit", requests=11),
    Scenario("redirects-off", f"{T}/redirect/302/redirects-off", 3600, 302, 0,
             "Redirect limit", settings={"max_redirects": "0"}, requests=1),
    Scenario("refused", "http://target:8090/", 15, 0, 0, "ConnectionRefusedError"),
    Scenario("hang", "http://target:8081/", 15, 0, 1,
             settings={"timeout": "5"}, max_total_time=7),
    Scenario("slow-body", f"{T}/slow-body/slow-body", 3600, 200, 1,
             settings={"timeout": "5"}, max_total_time=7),
    Scenario("trickled-body", f"{T}/trickle/trickled-body", 3600, 200, 1,
             settings={"timeout": "5"}, max_total_time=7),
    Scenario("dns-failure", "http://wptest.invalid/", 15, 0, 0, "gaierror"),
    Scenario("tls-valid", "https://target:8443/", 15, 200, 0),
    Scenario("tls-expired", "https://target:8444/", 15, 0, 0, "Expired certificate"),
    Scenario("tls-self-signed", "https://target:8445/", 15, 0, 0, "Self-signed certificate"),
    Scenario("tls-wrong-host", "https://target:8446/", 15, 0, 0, "Wrong hostname"),
    Scenario("proxy-ignored", f"{T}/status/200", 15, 200, 0,
             settings={"user_agent": "wptest-proxy-ignored"}),
]  # fmt: skip


def wait_for_events(stack: Stack, title: str) -> list[dict[str, str]]:
    searcher = stack.searcher("so1")
    return wait_for(
        INDEXED,
        lambda: searcher.search(events_query(title, stack.mark)) or None,
        EVENT_TIMEOUT,
        stack.stages,
    )


def squid_lines(stack: Stack, user_agent: str) -> int:
    return sum(
        1 for line in stack.logs("squid").splitlines() if f'ua="{user_agent}"' in line
    )


def check_proxy_ignored(stack: Stack) -> None:
    control = stack.exec(
        "so1",
        f"curl -sS -o /dev/null -w '%{{http_code}}' -x {PROXY} -A wptest-control {T}/status/200\n",
    )
    assert control.strip() == "200", (
        f"control request through Squid returned {control!r}"
    )
    wait_for(
        "squid logged the control",
        lambda: True if squid_lines(stack, "wptest-control") else None,
        30,
        stack.stages,
        interval=1,
    )
    environment = stack.input_process("so1")
    for name in PROXY_VARIABLES:
        assert environment.get(name) == PROXY, f"{name} in the input's environment"
    time.sleep(QUIET_WINDOW)
    assert squid_lines(stack, "wptest-proxy-ignored") == 0, "the input used the proxy"


def test_config_app_matches_the_table() -> None:
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    parser.read(APPS_DIR / "standalone" / "default" / "inputs.conf", encoding="utf-8")
    for scenario in SCENARIOS:
        section = dict(parser[f"web_ping://{scenario.title}"])
        expected = {
            "title": scenario.title,
            "url": scenario.url,
            "interval": str(scenario.interval),
            **scenario.settings,
        }
        assert section == expected, scenario.title


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda scenario: scenario.title)
def test_scenario(standalone: Stack, scenario: Scenario, evidence: Evidence) -> None:
    events = wait_for_events(standalone, scenario.title)
    if scenario.title == "proxy-ignored":
        check_proxy_ignored(standalone)
    searched_at = time.time()
    requests = standalone.target_requests(scenario.title) if scenario.requests else None
    diffs = compare(
        scenario,
        events,
        host="so1",
        mark=standalone.mark,
        searched_at=searched_at,
        requests=requests,
    )
    evidence.note(
        f"{standalone.project}.scenario.{scenario.title}", [str(diff) for diff in diffs]
    )
    if diffs:
        pytest.fail(describe(scenario, diffs), pytrace=False)
