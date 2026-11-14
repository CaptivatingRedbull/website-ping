"""Install, defaults inherited from the app, logging and the interpreter in use."""

from __future__ import annotations

import os
import re

import pytest
from wptest import install
from wptest.evidence import Evidence
from wptest.install import Package
from wptest.splunk_rest import events_query
from wptest.stack import SPLUNK, Stack
from wptest.versions import Runtime
from wptest.wait import wait_for

pytestmark = pytest.mark.single

SECOND_EVENT_TIMEOUT = 420
EVENT_TIMEOUT = 120
APP_INPUTS = "/opt/splunk/etc/apps/website_ping/default/inputs.conf"


def errors_query(since: float, stanza_filter: str) -> str:
    return (
        "search index=_internal source=*splunkd.log* component=ExecProcessor"
        f" log_level=ERROR _index_earliest={int(since)} {stanza_filter} | table _time _raw"
    )


def test_install_verified(standalone: Stack, package: Package) -> None:
    assert install.verify_install(standalone, "so1", package) == []
    assert standalone.rest("so1").app(install.APP)["version"] == package.version


def test_btool_shows_app_defaults(standalone: Stack) -> None:
    output = standalone.exec("so1", f"{SPLUNK} btool inputs list web_ping --debug\n")
    from_app = {
        line.split(None, 1)[1].strip()
        for line in output.splitlines()
        if line.startswith(APP_INPUTS)
    }
    for setting in ("sourcetype = website-ping", "interval = 300"):
        assert setting in from_app, f"{setting!r} not set by the app:\n{output}"
    # Code defaults apply; a default here would replace the unlimited redirects.
    for key in ("timeout", "max_redirects", "user_agent"):
        assert not any(line.startswith(f"{key} ") for line in from_app), output


def start_line_query(since: float) -> str:
    return (
        "search index=_internal source=*splunkd.log* component=ExecProcessor"
        f' "stanza=web_ping://status-200 starting check" _index_earliest={int(since)}'
        " | head 1 | table _raw"
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
    match = re.search(r' python=(\S+) openssl="[^"]+"', raw)
    assert match is not None, raw
    assert match.group(1).startswith(f"{runtime.python}."), raw


def test_bad_config_logs_error_and_writes_no_event(standalone: Stack) -> None:
    searcher = standalone.searcher("so1")
    errors = wait_for(
        "bad-config ERROR line",
        lambda: (
            searcher.search(
                errors_query(standalone.mark, '"stanza=web_ping://bad-config"')
            )
            or None
        ),
        EVENT_TIMEOUT,
        standalone.stages,
    )
    assert errors
    events = searcher.search(
        'search index=main sourcetype=website-ping source="web_ping://bad-config"'
        f" _index_earliest={int(standalone.mark)}"
    )
    assert events == []


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
    assert {event["sourcetype"] for event in events} == {"website-ping"}
    times = sorted(float(event["wptest_time"]) for event in events)
    assert abs(times[1] - times[0] - 300) <= 30, (
        f"events {times[1] - times[0]:.0f} s apart"
    )


def test_no_error_lines_for_other_stanzas(standalone: Stack) -> None:
    errors = standalone.searcher("so1").search(
        errors_query(
            standalone.mark, '"stanza=web_ping://" NOT "stanza=web_ping://bad-config"'
        )
    )
    assert errors == [], errors
