"""Every row of the scenario table, on the standalone stack."""

from __future__ import annotations

import configparser
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import pytest
from wptest.contract import Scenario, compare, describe
from wptest.evidence import Evidence
from wptest.install import APPS_DIR
from wptest.splunk_rest import body_count_query, events_query
from wptest.stack import Stack
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.network

EVENT_TIMEOUT = 120
PROXY = "http://squid:3128"
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
QUIET_WINDOW = 45
T = "http://target:8080"
ENV_PROXIED = "http://env-proxied:8080"
"""The target under a name that is not in NO_PROXY."""
HARNESS_CA = "/tmp/wptest-ca.pem"
VERIFIED = {"ssl_verify": "true", "ca_certs": HARNESS_CA}
"""Certificate checks against the harness CA. With the default (no checks), the
TLS targets are covered by the parity scenarios."""

SCENARIOS = [
    Scenario("status-200", f"{T}/status/200", 15, 200, False),
    Scenario("status-404", f"{T}/status/404", 15, 404, False),
    Scenario("status-503", f"{T}/status/503", 15, 503, False),
    Scenario("match-on-404", f"{T}/status/404", 15, 404, False,
             settings={"should_contain_string": "ok"}, has_expected_string=True),
    Scenario("body-on", f"{T}/big/10/body-on", 15, 200, False,
             settings={"return_body": "true"}, body_event=True),
    Scenario("body-off", f"{T}/big/10/body-off", 15, 200, False,
             settings={"return_body": "false"}),
    Scenario("body-empty", f"{T}/big/0/body-empty", 15, 200, False,
             settings={"return_body": "true"}),
    Scenario("chain-at-3", f"{T}/chain/chain-at-3/3", 3600, 200, False,
             settings={"max_redirects": "3"}, requests=4),
    Scenario("chain-at-10", f"{T}/chain/chain-at-10/10", 3600, 200, False, requests=11),
    Scenario("chain-at-50", f"{T}/chain/chain-at-50/50", 3600, 200, False,
             settings={"max_redirects": "50"}, requests=51),
    Scenario("repeat-8", f"{T}/repeat/repeat-8/8", 3600, 200, False,
             settings={"max_redirects": "10"}, requests=9),
    *[
        Scenario(f"redirect-{status}", f"{T}/redirect/{status}/redirect-{status}",
                 3600, 200, False, requests=2)
        for status in (301, 302, 303, 307, 308)
    ],
    Scenario("over-3", f"{T}/chain/over-3/4", 3600, None, False, "Redirect limit",
             settings={"max_redirects": "3"}, requests=4, exceeded_redirects=True),
    Scenario("over-10", f"{T}/chain/over-10/11", 3600, None, False, "Redirect limit",
             settings={"max_redirects": "10"}, requests=11, exceeded_redirects=True),
    Scenario("over-50", f"{T}/chain/over-50/51", 3600, None, False, "Redirect limit",
             settings={"max_redirects": "50"}, requests=51, exceeded_redirects=True),
    Scenario("loop", f"{T}/loop/loop", 3600, None, False, "Redirect limit",
             settings={"max_redirects": "10"}, requests=11, exceeded_redirects=True),
    Scenario("redirects-off", f"{T}/redirect/302/redirects-off", 3600, None, False,
             "Redirect limit", settings={"max_redirects": "0"}, requests=1,
             exceeded_redirects=True),
    Scenario("refused", "http://target:8090/", 15, None, False, "ConnectionRefusedError"),
    Scenario("hang", "http://target:8081/", 15, None, True,
             settings={"timeout": "5"}, max_duration=7),
    Scenario("slow-body", f"{T}/slow-body/slow-body", 3600, None, True,
             settings={"timeout": "5"}, max_duration=7),
    Scenario("trickled-body", f"{T}/trickle/trickled-body", 3600, None, True,
             settings={"timeout": "5"}, max_duration=7),
    Scenario("dns-failure", "http://wptest.invalid/", 15, None, False, "gaierror"),
    Scenario("tls-valid", "https://target:8443/", 15, 200, False, settings=VERIFIED),
    Scenario("tls-expired", "https://target:8444/", 15, None, False, "Expired certificate",
             settings=VERIFIED),
    Scenario("tls-self-signed", "https://target:8445/", 15, None, False,
             "Self-signed certificate", settings=VERIFIED),
    Scenario("tls-wrong-host", "https://target:8446/", 15, None, False, "Wrong hostname",
             settings=VERIFIED),
    # SSL_CERT_FILE in the stack points at the harness CA.
    Scenario("tls-verify-default-store", "https://target:8443/", 15, 200, False,
             settings={"ssl_verify": "true"}),
    Scenario("tls-bad-ca-path", "https://target:8443/", 15, None, False,
             "ca_certs not readable",
             settings={"ssl_verify": "true", "ca_certs": "/nonexistent.pem"}),
    Scenario("tls-old-protocol", "https://target:8448/", 15, None, False,
             "TLS handshake failed"),
    Scenario("proxy-env", f"{ENV_PROXIED}/status/200", 15, 200, False,
             settings={"user_agent": "wptest-proxy-env"}),
    Scenario("proxy-env-ignored", f"{ENV_PROXIED}/status/200", 15, 200, False,
             settings={"configuration": "ignore-all",
                       "user_agent": "wptest-proxy-env-ignored"}),
]  # fmt: skip


def body_events(stack: Stack, title: str) -> int:
    rows = stack.searcher("so1").search(body_count_query(title, stack.mark))
    return int(rows[0]["count"]) if rows else 0


def wait_for_events(stack: Stack, title: str) -> list[dict[str, str]]:
    searcher = stack.searcher("so1")
    return wait_for(
        INDEXED,
        lambda: searcher.search(events_query(title, stack.mark)) or None,
        EVENT_TIMEOUT,
        stack.stages,
    )


def request_times(stack: Stack, scenario: Scenario) -> list[float]:
    """Log times of the target requests on the scenario's port whose path has the
    title as one segment or is the URL's path (the silent port logs an empty path)."""
    url = urlsplit(scenario.url)
    times: list[float] = []
    for record in stack.target_log():
        path = str(record.get("path", "")).split("?", 1)[0]
        if int(str(record.get("port", 0))) != url.port:
            continue
        if scenario.title in path.split("/") or path in ("", url.path):
            times.append(float(str(record.get("time", 0))))
    return times


def squid_lines(stack: Stack, user_agent: str) -> int:
    return sum(
        1 for line in stack.logs("squid").splitlines() if f'ua="{user_agent}"' in line
    )


def check_input_environment(stack: Stack) -> None:
    environment = stack.input_process("so1")
    for name in PROXY_VARIABLES:
        assert environment.get(name) == PROXY, f"{name} in the input's environment"


def check_env_proxy_used(stack: Stack) -> None:
    check_input_environment(stack)
    wait_for(
        "squid logged the input",
        lambda: True if squid_lines(stack, "wptest-proxy-env") else None,
        30,
        stack.stages,
        interval=1,
    )


def check_env_proxy_ignored(stack: Stack) -> None:
    control = stack.exec(
        "so1",
        f"curl -sS -o /dev/null -w '%{{http_code}}' --noproxy '' -x {PROXY}"
        f" -A wptest-control {T}/status/200\n",
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
    check_input_environment(stack)
    time.sleep(QUIET_WINDOW)
    assert squid_lines(stack, "wptest-proxy-env-ignored") == 0, (
        "the input used the proxy"
    )


PROXY_CHECKS: dict[str, Callable[[Stack], None]] = {
    "proxy-env": check_env_proxy_used,
    "proxy-env-ignored": check_env_proxy_ignored,
}
"""Checks of the Squid log after a scenario's events arrived."""


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
    if scenario.title in PROXY_CHECKS:
        PROXY_CHECKS[scenario.title](standalone)
    searched_at = time.time()
    requests = standalone.target_requests(scenario.title) if scenario.requests else None
    times = request_times(standalone, scenario) if scenario.max_duration else []
    diffs = compare(
        scenario,
        events,
        host="so1",
        mark=standalone.mark,
        searched_at=searched_at,
        requests=requests,
        request_times=times,
        body_events=body_events(standalone, scenario.title),
    )
    evidence.note(
        f"{standalone.project}.scenario.{scenario.title}", [str(diff) for diff in diffs]
    )
    if diffs:
        pytest.fail(describe(scenario, diffs), pytrace=False)
