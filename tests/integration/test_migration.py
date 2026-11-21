"""The migration from Website Monitoring 2.9.7, done the way docs/migration.md
says, and the rollback.

The setup installs 2.9.7 with a local configuration that has plain-text
passwords and an input in the search app, applies the guide's changes before the
migration, and migrates with the guide's commands and file tables
(wptest/migration_steps.py). These tests check the result in the order an admin
would; the last ones stop the runner and roll back, so they come last.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from functools import partial
from typing import cast

import pytest
from wptest import golden, legacy, migration
from wptest.credentials import credential_forms, grep_script, parse_grep
from wptest.evidence import Evidence
from wptest.install import ROOT
from wptest.migration_steps import (
    APP_DIR,
    SERVICE,
    Migration,
    check_events,
    events_from,
    migration_of,
    quick_stanzas,
    roll_back,
)
from wptest.splunk_rest import error_lines_query
from wptest.stack import Stack
from wptest.versions import Runtime
from wptest.views import SEARCHES, ViewSearch, results_in_app
from wptest.wait import INDEXED, wait_for

pytestmark = pytest.mark.migration

GOLDEN_DIR = ROOT / "tests" / "golden" / legacy.LEGACY_VERSION
EVENT_TIMEOUT = 180
ALERT_TIMEOUT = 240
FIRST_RUN_SLACK = 30.0
"""Seconds from when a stanza is due (or the runner started) to the end of its
first check: one scheduling pass, the first configuration load and a check that
may run into its 5 s timeout."""
LONGEST_WAIT = 7 * 60
"""The test waits for the first check of stanzas due up to this long after the
runner started (the 10m input); stanzas due later are only checked for having
no event yet."""
SILENT_AFTER = 10 * 60
SILENT_TIMEOUT = 14 * 60
HEARTBEAT_TIMEOUT = 180
RUNNER_SILENT_RUNTIMES = ("9.4-py3.9", "10.6-py3.13")
OLD_USER_AGENT = "Splunk Website Monitoring"
USER_SEARCH = "Failed checks today"
ALERT = "Website Performance Problem"
RUNNER_SILENT = "Website Ping Runner Silent"

Row = dict[str, golden.FieldValue]


def single(value: golden.FieldValue | None) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else (value[0] if value else "")


def values(value: golden.FieldValue | None) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def rows_by_title(rows: Sequence[Row]) -> dict[str, Row]:
    return {single(row.get("title")): row for row in rows}


def guide() -> str:
    return migration.GUIDE.read_text(encoding="utf-8")


def with_old_app(stack: Stack) -> Migration:
    """The migration of a stack that ran Website Monitoring 2.9.7; the test is
    skipped on a fresh host."""
    state = migration_of(stack)
    if state.fresh:
        pytest.skip(
            f"Website Monitoring 2.9.7 installs on {legacy.LEGACY_LINE} only;"
            " this host starts from its copied files"
        )
    return state


# ---- before the migration -------------------------------------------------------


def test_old_app_ran_every_quick_input_after_the_changes(
    migration_stack: Stack,
) -> None:
    """With the plain-text passwords stored in search and removed from the files,
    2.9.7 still gets in: the guide's claim that nothing breaks before the
    switch."""
    state = with_old_app(migration_stack)
    assert set(quick_stanzas()) <= set(state.legacy_events)
    codes = {
        source: single(row.get("response_code"))
        for source, row in state.legacy_events.items()
    }
    for title in ("basic-plain", "basic-secure", "url-credentials", "proxy-auth"):
        assert codes[f"web_ping://{title}"] == "200", codes


def test_old_app_had_a_checkpoint_for_every_input(migration_stack: Stack) -> None:
    state = with_old_app(migration_stack)
    missing = [stanza for stanza, last in state.checkpoints.items() if last is None]
    assert missing == []


# ---- files ----------------------------------------------------------------------


def test_files_copied_as_the_guide_says(migration_stack: Stack) -> None:
    state = migration_of(migration_stack)
    assert state.plan is not None
    copied = {
        "local/eventtypes.conf",
        "local/inputs.conf",
        "local/macros.conf",
        "local/savedsearches.conf",
        "local/website_monitoring.conf",
    }
    if not state.fresh:
        copied.add("local/passwords.conf")
    assert set(state.plan.copy) == copied
    assert state.plan.merge == (() if state.fresh else ("metadata/local.meta",))
    assert "local/app.conf" in state.plan.left
    if not state.fresh:
        # Only an installed old app has its own copy of the lookup, which the
        # guide says to skip.
        assert "lookups/http_response_codes.csv" in state.plan.left
    present = migration_stack.exec(SERVICE, f"cd {APP_DIR}\nls local\n").split()
    assert {r.split("/", 1)[1] for r in state.plan.copy} <= set(present)


def test_local_meta_keeps_the_old_apps_stanzas(migration_stack: Stack) -> None:
    state = with_old_app(migration_stack)
    assert state.local_meta
    assert "[app/install/install_source_checksum]" in state.local_meta


def test_no_plain_text_password_in_website_ping_files(migration_stack: Stack) -> None:
    secrets = {
        f"secret {number}": credential_forms("wptest-scan", secret)
        for number, secret in enumerate(migration.PLAIN_SECRETS)
    }
    output = migration_stack.exec(
        SERVICE, grep_script(secrets, ("/opt/splunk/etc/apps/website_ping*",))
    )
    assert parse_grep(output) == []


# ---- after the start ------------------------------------------------------------


def test_guide_searches_after_the_start(
    migration_stack: Stack, evidence: Evidence
) -> None:
    """The two searches of "After the start": no input with an ERROR, and events
    from every quick input."""
    problems, arriving = migration.after_start_searches(guide())
    rest = migration_stack.rest(SERVICE)
    state = migration_of(migration_stack)
    lines = results_in_app(rest, f"{problems} _index_earliest={int(state.started_at)}")
    evidence.note(
        f"{migration_stack.project}.migration.warnings",
        [single(row.get("_raw")) for row in lines],
    )
    errors = [
        single(row.get("_raw")) for row in lines if " ERROR " in single(row.get("_raw"))
    ]
    assert errors == []
    sources = {single(row.get("source")) for row in results_in_app(rest, arriving)}
    assert set(quick_stanzas()) <= sources


def test_no_error_line_from_website_ping(migration_stack: Stack) -> None:
    state = migration_of(migration_stack)
    errors = migration_stack.searcher(SERVICE).search(
        error_lines_query(
            f"source=*website_ping.log* _index_earliest={int(state.started_at)}"
        )
    )
    assert errors == [], errors


def test_schedule_continues_from_the_old_checkpoints(
    migration_stack: Stack, evidence: Evidence
) -> None:
    """Each input's first check after the switch ends when the old checkpoint
    makes it due, or right after the runner started when that time has passed;
    an input due later has no event before then."""
    state = with_old_app(migration_stack)
    started = state.runner_started
    windows: dict[str, tuple[float, float]] = {}
    for item in migration.LEGACY_INPUTS:
        last_run = state.checkpoints[item.stanza]
        assert last_run is not None, item.stanza
        windows[item.stanza] = migration.first_run_window(
            last_run, item.seconds, started, FIRST_RUN_SLACK
        )
    awaited = [
        s for s, (earliest, _) in windows.items() if earliest <= started + LONGEST_WAIT
    ]
    assert any(windows[s][0] > started for s in awaited), "no input due after the start"
    events = wait_for(
        INDEXED,
        partial(events_from, migration_stack, state.started_at, awaited),
        LONGEST_WAIT + EVENT_TIMEOUT,
        migration_stack.stages,
        interval=15,
    )
    now = time.time()
    seen: dict[str, float | None] = {}
    problems: list[str] = []
    for stanza, (earliest, latest) in windows.items():
        rows = events.get(stanza, [])
        first = golden.event_time(rows[0]) if rows else None
        seen[stanza] = first
        if first is None:
            if earliest <= now:
                problems.append(f"{stanza}: no event, due at {earliest:.0f}")
        elif not earliest <= first <= latest:
            problems.append(
                f"{stanza}: first check ended at {first:.1f}, expected"
                f" {earliest:.1f} to {latest:.1f}"
            )
    evidence.note(
        f"{migration_stack.project}.migration.schedule",
        {
            "runner_started": started,
            "checkpoints": state.checkpoints,
            "windows": windows,
            "first_event": seen,
        },
    )
    assert problems == []


@pytest.mark.parametrize(
    "item",
    [i for i in migration.LEGACY_INPUTS if i.scenario is not migration.URL_CREDENTIALS],
    ids=lambda i: i.title,
)
def test_event_matches_golden(
    migration_stack: Stack, item: migration.LegacyInput, evidence: Evidence
) -> None:
    state = migration_of(migration_stack)
    rows = check_events(migration_stack, state.started_at).get(item.stanza)
    if not rows:
        pytest.skip(f"{item.title}: not due during the test (every {item.interval})")
    fixture = golden.read_capture(GOLDEN_DIR, item.title)
    expected = [e for e in fixture.events if e.sourcetype == golden.CHECK_SOURCETYPE][
        -1
    ]
    actual = golden.event_from_result(rows[-1])
    diffs = golden.compare(
        expected, actual, golden.parity_allowed(item.title, expected)
    )
    evidence.note(
        f"{migration_stack.project}.migration.golden.{item.title}",
        [str(d) for d in diffs],
    )
    failing = [str(d) for d in golden.failing(diffs)]
    if actual.fields.get("_time") != golden.TIME:
        failing.append(
            f"_time: expected the time of the check, got {actual.fields.get('_time')}"
        )
    assert failing == [], actual.raw


def test_url_credentials_moved_to_username(migration_stack: Stack) -> None:
    state = migration_of(migration_stack)
    stanza = migration.URL_CREDENTIALS
    rows = check_events(migration_stack, state.started_at)[f"web_ping://{stanza.title}"]
    newest = rows[-1]
    assert single(newest.get("response_code")) == "200"
    assert "@" not in single(newest.get("url"))


# ---- knowledge objects ------------------------------------------------------------


def test_macro_overrides_apply(migration_stack: Stack) -> None:
    rest = migration_stack.rest(SERVICE)
    (row,) = results_in_app(
        rest,
        "| makeresults | eval threshold=`response_time_threshold` | table threshold",
    )
    assert single(row.get("threshold")) == "250"
    entry = rest.get(
        "/servicesNS/nobody/website_ping/configs/conf-macros/website_monitoring_search_index"
    )
    entries = cast("list[dict[str, dict[str, object]]]", entry["entry"])
    assert entries[0]["content"]["definition"] == "index=main"
    assert results_in_app(
        rest, "`website_monitoring_search_index` sourcetype=web_ping | head 1"
    )


def test_eventtype_override_tags_the_excluded_site(migration_stack: Stack) -> None:
    state = migration_of(migration_stack)
    rows = results_in_app(
        migration_stack.rest(SERVICE),
        f"index=main sourcetype=web_ping _index_earliest={int(state.started_at)}"
        " (title=status-503 OR title=status-200) | dedup title | table title tag",
    )
    tags = {title: values(row.get("tag")) for title, row in rows_by_title(rows).items()}
    assert "exclude_from_alerts" in tags["status-503"]
    assert "exclude_from_alerts" not in tags["status-200"]


def test_alert_reports_failures_but_not_the_excluded_site(
    migration_stack: Stack,
) -> None:
    rows = rows_by_title(
        results_in_app(migration_stack.rest(SERVICE), f'| savedsearch "{ALERT}"')
    )
    assert "status-503" not in rows
    assert single(rows["refused"].get("description")) == "Connection failed"
    assert single(rows["timeout"].get("description")) == "Connection timed out"


def alert_events(stack: Stack, since: float) -> list[Row] | None:
    rows = results_in_app(
        stack.rest(SERVICE),
        f"index=main sourcetype=wptest:alert _index_earliest={int(since)} | table _raw source",
    )
    return rows or None


def test_scheduled_alert_fires_and_logs_an_event(migration_stack: Stack) -> None:
    """The copied override runs the alert every minute with the Log Event
    action; the scheduler names website_ping as its app."""
    state = migration_of(migration_stack)
    rows = wait_for(
        "alert event",
        partial(alert_events, migration_stack, state.started_at),
        ALERT_TIMEOUT,
        migration_stack.stages,
        interval=15,
    )
    raws = [single(row.get("_raw")) for row in rows]
    assert any(f'wptest-alert name="{ALERT}"' in raw for raw in raws), raws
    runs = results_in_app(
        migration_stack.rest(SERVICE),
        f'index=_internal sourcetype=scheduler savedsearch_name="{ALERT}"'
        f" _index_earliest={int(state.started_at)} | stats count by app",
    )
    apps = {single(row.get("app")) for row in runs}
    assert "website_ping" in apps, runs
    assert legacy.LEGACY_APP not in apps, runs


def test_user_saved_search_runs(migration_stack: Stack) -> None:
    rows = results_in_app(
        migration_stack.rest(SERVICE), f'| savedsearch "{USER_SEARCH}"'
    )
    assert rows
    columns = {key for row in rows for key in row if not key.startswith("_")}
    assert columns <= {"time", "title", "url", "response_code", "response_time"}
    codes = {
        title: single(row.get("response_code"))
        for title, row in rows_by_title(rows).items()
    }
    assert codes["refused"] == "Connection failed"


@pytest.mark.parametrize("search", SEARCHES, ids=[s.id for s in SEARCHES])
def test_view_search_runs(migration_stack: Stack, search: ViewSearch) -> None:
    _ = results_in_app(migration_stack.rest(SERVICE), search.query)


# ---- these stop the runner and roll back: keep them last -------------------------


def heartbeat_indexed(stack: Stack, since: float) -> list[Row] | None:
    rows = results_in_app(
        stack.rest(SERVICE),
        "index=_internal source=*website_ping.log* heartbeat"
        f" _index_earliest={int(since)} | stats count by host",
    )
    return rows or None


def runner_silent_rows(stack: Stack) -> list[Row] | None:
    rows = results_in_app(stack.rest(SERVICE), f'| savedsearch "{RUNNER_SILENT}"')
    return rows or None


def test_runner_silent_alert_after_the_runner_stops(
    migration_stack: Stack, runtime: Runtime
) -> None:
    """No row while the runner logs heartbeats; one row for the host once the
    stopped runner has been silent for 10 minutes. The alert only knows hosts
    that logged a heartbeat, and a runner logs its first one a minute after it
    starts, so the runner is stopped only once that one is indexed."""
    if runtime.id not in RUNNER_SILENT_RUNTIMES:
        pytest.skip(f"runs on {', '.join(RUNNER_SILENT_RUNTIMES)} only (11 minutes)")
    state = migration_of(migration_stack)
    _ = wait_for(
        "heartbeat indexed",
        partial(heartbeat_indexed, migration_stack, state.runner_started),
        HEARTBEAT_TIMEOUT,
        migration_stack.stages,
        interval=10,
    )
    assert runner_silent_rows(migration_stack) is None
    pids = migration_stack.input_pids(SERVICE)
    assert len(pids) == 1, pids
    migration_stack.exec(SERVICE, f"kill -STOP {pids[0]}\n")
    stopped = time.time()
    try:
        time.sleep(SILENT_AFTER)
        rows = wait_for(
            "runner reported silent",
            partial(runner_silent_rows, migration_stack),
            SILENT_TIMEOUT - SILENT_AFTER,
            migration_stack.stages,
            interval=20,
        )
    finally:
        migration_stack.exec(SERVICE, f"kill -CONT {pids[0]}\n")
    assert len(rows) == 1, rows
    assert single(rows[0].get("host"))
    assert time.time() - stopped >= SILENT_AFTER


NO_REQUEST_LOGGED = ("refused", "timeout")
"""Quick inputs whose checks leave no request with a user agent in the target's
log: a closed port and a port that never answers."""


def old_app_requests(stack: Stack, since: float) -> list[str] | None:
    """Quick inputs the old app sent a request for since since, once every input
    that leaves one in the target's log has."""
    records = [
        record
        for record in stack.target_log()
        if float(str(record.get("time", 0))) >= since
        and str(record.get("user_agent", "")).startswith(OLD_USER_AGENT)
    ]
    expected = [
        item
        for item in migration.LEGACY_INPUTS
        if item.seconds <= 60 and item.title not in NO_REQUEST_LOGGED
    ]
    found = [
        item.title
        for item in expected
        if any(
            item.scenario.matches_request(
                int(str(record.get("port", 0))), str(record.get("path", ""))
            )
            for record in records
        )
    ]
    return found if len(found) == len(expected) else None


def test_rollback_brings_the_old_app_back(
    migration_stack: Stack, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The guide's rollback: the old app checks the sites again, with its own
    user agent, and its events keep the sourcetype web_ping."""
    _ = with_old_app(migration_stack)
    since = time.time()
    changed = roll_back(migration_stack, tmp_path_factory.mktemp("rollback"))
    assert changed == []
    apps = migration_stack.exec(SERVICE, "ls /opt/splunk/etc/apps\n").split()
    assert legacy.LEGACY_APP in apps
    assert "website_ping" not in apps
    _ = wait_for(
        "old app's requests",
        partial(old_app_requests, migration_stack, since),
        EVENT_TIMEOUT,
        migration_stack.stages,
        interval=10,
    )
    events = wait_for(
        INDEXED,
        partial(events_from, migration_stack, since, quick_stanzas()),
        EVENT_TIMEOUT,
        migration_stack.stages,
    )
    assert all(
        single(rows[-1].get("sourcetype")) == "web_ping" for rows in events.values()
    )
