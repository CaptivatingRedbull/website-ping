"""Install, defaults inherited from the app, logging, the interpreter in use and
the single input process with its schedule.

The last tests restart Splunk, change the configuration and stop Splunk; they run
after every other test on the standalone stack (test_network sorts before this
file, and the order inside a file is kept).
"""

from __future__ import annotations

import configparser
import hashlib
import os
import re
import time

import pytest
from wptest import flavor, install
from wptest.evidence import Evidence
from wptest.install import (
    APPS_DIR,
    CONFIG_APP,
    RESTART_TIMEOUT,
    STORED_PASSWORD,
    STORED_PASSWORD_STANZA,
    Package,
)
from wptest.splunk_rest import Searcher, error_lines_query, events_query
from wptest.stack import SPLUNK, Stack
from wptest.versions import Runtime
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.single

SECOND_EVENT_TIMEOUT = 420
EVENT_TIMEOUT = 120
AFTER_RESTART = 120
STOP_LIMIT = 3.0
APP_INPUTS = "/opt/splunk/etc/apps/website_ping/default/inputs.conf"
INVALID_STANZAS = {
    "bad-config": "url must use http or https",
    "no-interval": "interval is required",
    "proxy-socks": (
        "{conf_file} stanza socks cannot be used, not run:"
        " proxy_type = socks5 is not supported, only HTTP proxies are"
    ),
    "password-plain-rejected": (
        "password in inputs.conf is not supported; store it in storage/passwords"
        " with realm {scheme}://password-plain-rejected"
    ),
}
"""The ERROR line of each stanza that does not run; {conf_file} and {scheme} are
the names of the build under test (expected_error)."""
SETUP_ERROR_STANZAS = {
    "tls-bad-ca-path": "TLS setup failed: ca_certs not readable",
}
"""Stanzas that run, but log one ERROR line per process about their settings."""


def expected_error(name: str) -> str:
    under_test = flavor.current()
    return INVALID_STANZAS[name].format(
        conf_file=under_test.conf_file, scheme=under_test.scheme
    )


def stanza_filter(name: str = "") -> str:
    """Search clause for the log lines of a stanza (or, without a name, of any)."""
    return f'"stanza={flavor.current().stanza(name)}"'


def standalone_stanzas() -> dict[str, dict[str, str]]:
    """The stanzas of the standalone config app, by name without the scheme."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(
        APPS_DIR / "standalone" / "default" / "inputs.conf", encoding="utf-8"
    )
    return {
        section.split("://", 1)[1]: dict(parser[section])
        for section in parser.sections()
    }


def counted_stanzas() -> list[str]:
    """Stanzas checked once an hour: exactly one event in a test run."""
    return [
        name
        for name, values in standalone_stanzas().items()
        if values.get("interval") == "3600"
    ]


def event_counts(searcher: Searcher, since: float) -> dict[str, int]:
    """web_ping events indexed since the mark, by source."""
    rows = searcher.search(
        f"search index=main sourcetype=web_ping _index_earliest={int(since)}"
        " | stats count by source"
    )
    return {row["source"]: int(row["count"]) for row in rows}


def errors_query(since: float, stanza_filter: str) -> str:
    """ERROR lines of the input's log file indexed since the mark."""
    return error_lines_query(
        f"source=*website_ping.log* _index_earliest={int(since)} {stanza_filter}"
    )


def test_install_verified(standalone: Stack, package: Package) -> None:
    assert install.verify_install(standalone, "so1", package) == []
    assert standalone.rest("so1").app(install.APP)["version"] == package.version


def test_btool_shows_app_defaults(standalone: Stack) -> None:
    scheme = flavor.current().scheme
    output = standalone.exec("so1", f"{SPLUNK} btool inputs list {scheme} --debug\n")
    from_app = {
        line.split(None, 1)[1].strip()
        for line in output.splitlines()
        if line.startswith(APP_INPUTS)
    }
    assert "sourcetype = web_ping" in from_app, output
    # Code defaults apply; a default here would replace the unlimited redirects.
    # interval has no default: a stanza without one is invalid, as in 2.9.7.
    for key in ("interval", "timeout", "max_redirects", "user_agent"):
        assert not any(line.startswith(f"{key} ") for line in from_app), output


def test_btool_check_accepts_the_conf_file(standalone: Stack) -> None:
    """btool check reads the shipped file and the test app's copy and reports
    nothing for them: the spec declares every key."""
    conf_file = flavor.current().conf_file
    output = standalone.exec("so1", f"{SPLUNK} btool check --debug 2>&1 || true\n")
    lines = {line.strip() for line in output.splitlines() if conf_file in line}
    assert lines == {
        f"Checking: /opt/splunk/etc/apps/{app}/default/{conf_file}"
        for app in (install.APP, CONFIG_APP)
    }, output


def start_line_query(since: float) -> str:
    return (
        'search index=_internal source=*website_ping.log* "starting stanzas="'
        f" _index_earliest={int(since)} | head 1 | table _raw sourcetype"
    )


def test_interpreter(standalone: Stack, runtime: Runtime, evidence: Evidence) -> None:
    exe = standalone.input_process("so1")["exe"]
    evidence.note(f"{standalone.project}.interpreter", exe)
    assert os.path.basename(exe) == runtime.interpreter
    searcher = standalone.searcher("so1")
    rows = wait_for(
        "start line with interpreter",
        lambda: searcher.search(start_line_query(standalone.mark)) or None,
        EVENT_TIMEOUT,
        standalone.stages,
    )
    raw = rows[0]["_raw"]
    evidence.note(f"{standalone.project}.start_line", raw)
    assert rows[0]["sourcetype"] == "website_ping:log", rows[0]
    match = re.search(r' python=(\S+) openssl="[^"]+" flavor=(\S+)', raw)
    assert match is not None, raw
    assert match.group(1).startswith(f"{runtime.python}."), raw
    assert match.group(2) == flavor.current().name, raw


def test_thread_limit_from_the_conf_file(standalone: Stack) -> None:
    """[default] of the config app's exported conf file (website_monitoring.conf,
    or website_ping.conf in the side-by-side build) reaches the input through
    website_ping's [wp_defaults]."""
    searcher = standalone.searcher("so1")
    rows = wait_for(
        "start line",
        lambda: searcher.search(start_line_query(standalone.mark)) or None,
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert " thread_limit=50 " in rows[0]["_raw"], rows[0]["_raw"]


def test_stored_password_is_found_and_never_logged(standalone: Stack) -> None:
    searcher = standalone.searcher("so1")
    stanza = flavor.current().stanza(STORED_PASSWORD_STANZA)
    _ = wait_for(
        "password found line",
        lambda: (
            searcher.search(
                "search index=_internal source=*website_ping.log*"
                f' "password found for stanza" "stanza={stanza}"'
                f" _index_earliest={int(standalone.mark)}"
            )
            or None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    leaked = searcher.search(
        f'search index=_internal "{STORED_PASSWORD}" _index_earliest={int(standalone.mark)}'
    )
    assert leaked == [], leaked


@pytest.mark.parametrize("name", sorted(INVALID_STANZAS))
def test_invalid_stanza_logs_error_and_writes_no_event(
    standalone: Stack, name: str
) -> None:
    searcher = standalone.searcher("so1")
    errors = wait_for(
        f"{name} ERROR line",
        lambda: (
            searcher.search(errors_query(standalone.mark, stanza_filter(name))) or None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert expected_error(name) in errors[0]["_raw"], errors
    events = searcher.search(
        f'search index=main sourcetype=web_ping source="{flavor.current().stanza(name)}"'
        f" _index_earliest={int(standalone.mark)}"
    )
    assert events == []


def test_plain_password_is_never_logged(standalone: Stack) -> None:
    name = "password-plain-rejected"
    secret = standalone_stanzas()[name]["password"]
    searcher = standalone.searcher("so1")
    _ = wait_for(
        f"{name} ERROR line",
        lambda: (
            searcher.search(errors_query(standalone.mark, stanza_filter(name))) or None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    leaked = searcher.search(
        f'search index=_internal "{secret}" _index_earliest={int(standalone.mark)}'
    )
    assert leaked == [], leaked


def test_one_process_runs_every_valid_stanza(standalone: Stack) -> None:
    pids = standalone.input_pids("so1")
    assert len(pids) == 1, f"{flavor.current().script} processes: {pids}"
    expected = {
        flavor.current().stanza(name)
        for name in standalone_stanzas()
        if name not in INVALID_STANZAS
    }
    searcher = standalone.searcher("so1")
    counts = wait_for(
        "an event of every valid stanza",
        lambda: (
            found
            if expected <= set(found := event_counts(searcher, standalone.mark))
            else None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert set(counts) == expected


def test_default_settings_inherited(standalone: Stack) -> None:
    searcher = standalone.searcher("so1")
    events = wait_for(
        "second default-settings event",
        lambda: (
            found
            if len(
                found := searcher.search(
                    events_query("default-settings", standalone.mark)
                )
            )
            >= 2
            else None
        ),
        SECOND_EVENT_TIMEOUT,
        standalone.stages,
        interval=15,
    )
    assert {event["sourcetype"] for event in events} == {"web_ping"}
    times = sorted(float(event["wptest_time"]) for event in events)
    assert abs(times[1] - times[0] - 300) <= 30, (
        f"events {times[1] - times[0]:.0f} s apart"
    )


def test_interval_with_unit(standalone: Stack) -> None:
    searcher = standalone.searcher("so1")
    events = wait_for(
        "second interval-units event",
        lambda: (
            found
            if len(
                found := searcher.search(
                    events_query("interval-units", standalone.mark)
                )
            )
            >= 2
            else None
        ),
        EVENT_TIMEOUT + 60,
        standalone.stages,
        interval=10,
    )
    times = sorted(float(event["wptest_time"]) for event in events)
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    assert all(55 <= gap <= 75 for gap in gaps), f"gaps {gaps}"


@pytest.mark.parametrize("name", sorted(SETUP_ERROR_STANZAS))
def test_setup_error_is_logged_once(standalone: Stack, name: str) -> None:
    searcher = standalone.searcher("so1")
    _ = wait_for(
        f"two {name} events",
        lambda: (
            found
            if len(found := searcher.search(events_query(name, standalone.mark))) >= 2
            else None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    errors = wait_for(
        f"{name} ERROR line",
        lambda: (
            searcher.search(errors_query(standalone.mark, stanza_filter(name))) or None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert len(errors) == 1, errors
    assert SETUP_ERROR_STANZAS[name] in errors[0]["_raw"], errors


def test_no_error_lines_for_other_stanzas(standalone: Stack) -> None:
    excluded = " ".join(
        f"NOT {stanza_filter(name)}"
        for name in [*INVALID_STANZAS, *SETUP_ERROR_STANZAS]
    )
    errors = standalone.searcher("so1").search(
        errors_query(standalone.mark, f"{stanza_filter()} {excluded}")
    )
    assert errors == [], errors


# ---- These change the stack: restart, configuration change, stop. Keep last. --


def test_restart_keeps_the_schedule(standalone: Stack) -> None:
    counted = counted_stanzas()
    sources = {flavor.current().stanza(name) for name in counted}
    searcher = standalone.searcher("so1")
    before = event_counts(searcher, standalone.mark)
    assert {s: before.get(s) for s in sources} == dict.fromkeys(sources, 1), before
    install.restart(standalone, "so1")
    time.sleep(AFTER_RESTART)
    after = event_counts(searcher, standalone.mark)
    assert {s: after.get(s) for s in sources} == dict.fromkeys(sources, 1), after
    checkpoints = flavor.current().checkpoint_dir
    files = set(standalone.exec("so1", f"ls {checkpoints}\n").split())
    for source in sources:
        digest = hashlib.sha224(source.encode("utf-8")).hexdigest()
        assert f"{digest}.json" in files, f"no checkpoint for {source}"


def test_stanza_added_through_rest_runs(standalone: Stack) -> None:
    since = time.time()
    _ = standalone.rest("so1").post(
        f"/servicesNS/nobody/{CONFIG_APP}/data/inputs/{flavor.current().scheme}",
        {
            "name": "rest-added",
            "title": "rest-added",
            "url": "http://target:8080/status/200",
            "interval": "3600",
        },
    )
    searcher = standalone.searcher("so1")
    events = wait_for(
        INDEXED,
        lambda: searcher.search(events_query("rest-added", since)) or None,
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert len(events) == 1
    # splunkd replaced the process; the old one stopped by itself.
    assert any(
        logged >= since - 1 and " stopped reason=SIGTERM " in line
        for logged, line in standalone.app_log("so1")
    )


def test_splunk_stop_ends_the_input_in_time(standalone: Stack) -> None:
    pids = wait_for(
        "input process",
        lambda: standalone.input_pids("so1") or None,
        60,
        standalone.stages,
        interval=1,
    )
    assert len(pids) == 1, pids
    own = re.compile(rf" pid={pids[0]}(?: |$)")
    try:
        _ = standalone.splunk("so1", "stop", timeout=RESTART_TIMEOUT)
        assert standalone.input_pids("so1") == []
        lines = [(t, line) for t, line in standalone.app_log("so1") if own.search(line)]
        stopping = [t for t, line in lines if " stopping reason=SIGTERM " in line]
        stopped = [t for t, line in lines if " stopped reason=SIGTERM " in line]
        # A process killed by splunkd never writes its stopped line.
        assert stopping and stopped, lines[-5:]
        assert stopped[-1] - stopping[0] <= STOP_LIMIT, (stopping, stopped)
    finally:
        _ = standalone.splunk(
            "so1", "start --answer-yes --no-prompt", timeout=RESTART_TIMEOUT
        )
        install.wait_running(standalone, "so1")
