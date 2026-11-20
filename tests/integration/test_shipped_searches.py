"""The app's saved searches and macros run on website-ping's events.

Runs on the parity stack, whose scenarios carry the titles of the golden
capture: the alert's rows are compared with the rows Website Monitoring 2.9.7's
alert returned there. Every search runs as admin in website_ping's namespace,
the way a dashboard or a scheduled search of the app runs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from functools import partial
from typing import cast

import pytest
from wptest import golden, legacy, searches
from wptest.conf import read_conf
from wptest.install import ROOT
from wptest.splunk_rest import SplunkRest
from wptest.stack import Stack
from wptest.wait import INDEXED, STARTED, wait_for

pytestmark = pytest.mark.parity

APP = "website_ping"
GOLDEN_DIR = ROOT / "tests" / "golden" / legacy.LEGACY_VERSION
SAVED_SEARCHES = ROOT / "default" / "savedsearches.conf"
EVENT_TIMEOUT = 180
HEARTBEAT_TIMEOUT = 180

FAILED = ("refused", "timeout", "status-503")
"""No connection, no response within the timeout, an error status."""
HEALTHY = ("status-200", "match-no")
"""A response below 400; match-no lacks the expected string."""
TITLES = FAILED + HEALTHY + ("thresholds",)

Row = dict[str, golden.FieldValue]


def base_query(stack: Stack, titles: Sequence[str] = TITLES) -> str:
    title_filter = " OR ".join(f"title={title}" for title in titles)
    return (
        "search index=main sourcetype=web_ping"
        f" ({title_filter}) _index_earliest={int(stack.mark)}"
    )


def run(rest: SplunkRest, query: str) -> list[Row]:
    """Final results of the query in the app's namespace; a search error fails."""
    text = rest.export_in_app(APP, query)
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


def by_title(rows: Sequence[Row], titles: Sequence[str] = TITLES) -> dict[str, Row]:
    return {str(row.get("title")): row for row in rows if row.get("title") in titles}


def shipped_search(name: str) -> str:
    return read_conf(SAVED_SEARCHES)[name]["search"]


def first_event(stack: Stack, title: str) -> list[dict[str, str]] | None:
    rows = stack.searcher("so1").search(f"{base_query(stack, (title,))} | head 1")
    return rows or None


@pytest.fixture
def stack(parity_stack: Stack) -> Stack:
    """The parity stack once every title used here has a check event."""
    for title in TITLES:
        _ = wait_for(
            INDEXED,
            partial(first_event, parity_stack, title),
            EVENT_TIMEOUT,
            parity_stack.stages,
        )
    return parity_stack


# ---- saved searches -------------------------------------------------------------


def expected_alert_rows() -> list[Mapping[str, object]]:
    """2.9.7's alert rows from the golden capture, with the timeout described as
    a timeout."""
    stored = cast("list[dict[str, object]]", searches.read(GOLDEN_DIR)["alert"]["rows"])
    rows = [dict(row) for row in stored]
    for row in rows:
        if row["title"] == "timeout":
            row["description"] = "Connection timed out"
    return sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))


def test_alert_reports_failures_like_website_monitoring(stack: Stack) -> None:
    """Same rows as 2.9.7's alert; a timeout reads "Connection timed out"."""
    recorded = next(s for s in searches.SEARCHES if s.name == "alert")
    rows = run(stack.rest("so1"), recorded.query)
    assert searches.normalise_rows(recorded, rows) == expected_alert_rows()


def test_inoperable_sites_counts_every_failure_as_down(stack: Stack) -> None:
    head, separator, _ = shipped_search("inoperable_sites_rangemap").partition(
        " | stats sum(down) as count"
    )
    assert separator
    rest = stack.rest("so1")
    down = {
        title: row.get("down")
        for title, row in by_title(
            run(rest, f"search {head} | table title down")
        ).items()
    }
    assert down == {
        "refused": "1",
        "timeout": "1",
        "status-503": "1",
        "status-200": "0",
        "match-no": "0",
        "thresholds": "0",
    }
    (result,) = run(rest, "| savedsearch inoperable_sites_rangemap")
    assert int(str(result["count"])) >= len(FAILED)
    assert result["range"] == "severe"


def test_availability_overview_names_failed_connections(stack: Stack) -> None:
    rows = run(stack.rest("so1"), "| savedsearch website_availability_overview")
    columns = {key for row in rows for key in row}
    assert columns == {
        "title",
        "url",
        "response_code",
        "last_checked",
        "time_exceeded",
        "response_time",
        "avg_time_exceeded",
        "average",
        "range",
        "sparkline_response_time",
    }
    codes = {title: row.get("response_code") for title, row in by_title(rows).items()}
    assert codes["refused"] == "Connection failed"
    assert codes["timeout"] == "Connection timed out"
    assert codes["status-503"] == "503"
    assert codes["status-200"] == "200"


def test_performance_problems_lists_failed_sites(stack: Stack) -> None:
    rows = run(stack.rest("so1"), "| savedsearch website_performance_problems")
    codes = {title: row.get("response_code") for title, row in by_title(rows).items()}
    assert codes == {
        "refused": "Connection failed",
        "timeout": "Connection timed out",
        "status-503": "503",
    }


@pytest.mark.parametrize("name", ["slow_sites_rangemap", "slow_sites_avg_rangemap"])
def test_slow_sites_rangemaps_return_a_count(stack: Stack, name: str) -> None:
    (result,) = run(stack.rest("so1"), f"| savedsearch {name}")
    assert int(str(result["count"])) >= 0
    assert result["range"] in ("low", "severe")


# ---- macros ---------------------------------------------------------------------


def test_status_after_set_response_code(stack: Stack) -> None:
    """set_status as the dashboards call it: after set_response_code. thresholds
    writes its own limits (100/200 ms) into its events, so its 300 ms response
    is Failed; the other inputs use the threshold macros."""
    rest = stack.rest("so1")
    rows = by_title(
        run(
            rest,
            f"{base_query(stack)} | dedup title | `set_response_code` | `set_status`"
            " | table title response_code status",
        )
    )
    assert {
        title: (row["response_code"], row["status"]) for title, row in rows.items()
    } == {
        "refused": ("Connection failed", "Failed"),
        "timeout": ("Connection timed out", "Failed"),
        "status-503": ("503", "Failed"),
        "status-200": ("200", "OK"),
        "match-no": ("200 false", "Failed"),
        "thresholds": ("200", "Failed"),
    }
    (thresholds,) = run(
        rest,
        f"{base_query(stack, ('thresholds',))} | head 1"
        " | eval error_threshold=200, warning_threshold=100"
        " | `set_response_code` | `set_status` | table title status",
    )
    assert thresholds["status"] == "Failed"


@pytest.mark.parametrize("macro", ["format_events_ex", "format_events_raw"])
def test_format_events_names_failed_connections(stack: Stack, macro: str) -> None:
    rows = by_title(
        run(
            stack.rest("so1"),
            f"{base_query(stack)} | dedup title | `{macro}`"
            " | table title response_code time",
        )
    )
    assert {title: row["response_code"] for title, row in rows.items()} == {
        "refused": "Connection failed",
        "timeout": "Connection timed out",
        "status-503": "503",
        "status-200": "200",
        "match-no": "200",
        "thresholds": "200",
    }
    assert all(row.get("time") for row in rows.values())


def test_format_events_columns(stack: Stack) -> None:
    rows = run(
        stack.rest("so1"),
        f"{base_query(stack, ('refused',))} | head 1 | `format_events`",
    )
    assert len(rows) == 1
    columns = {key for key in rows[0] if not key.startswith("_")}
    assert columns <= {"time", "response_code", "response_time"}
    assert rows[0]["response_code"] == "Connection failed"


@pytest.mark.parametrize(
    ("macro", "titles"),
    [
        ("filter_inoperable", {"refused", "timeout", "status-503"}),
        (
            "filter_response_codes_and_response_times",
            {"refused", "timeout", "status-503", "match-no"},
        ),
    ],
)
def test_filters_keep_failed_checks(stack: Stack, macro: str, titles: set[str]) -> None:
    rows = run(
        stack.rest("so1"), f"{base_query(stack)} (`{macro}`) | stats count by title"
    )
    assert {str(row["title"]) for row in rows} == titles


def test_filter_disabled_passes_every_result(stack: Stack) -> None:
    rows = run(
        stack.rest("so1"),
        f"{base_query(stack)} | dedup title `filter_disabled` | stats count by title",
    )
    assert {str(row["title"]) for row in rows} == set(TITLES)


# ---- runner alert ---------------------------------------------------------------


def heartbeat_hosts(rest: SplunkRest) -> list[Row] | None:
    rows = run(
        rest,
        "search index=_internal source=*website_ping.log* heartbeat"
        " | stats count by host",
    )
    return rows or None


def test_runner_silent_alert(parity_stack: Stack) -> None:
    """No row while the runner logs heartbeats; with the silence limit moved into
    the future, the same search reports the host with its last heartbeat."""
    rest = parity_stack.rest("so1")
    _ = wait_for(
        STARTED, lambda: heartbeat_hosts(rest), HEARTBEAT_TIMEOUT, parity_stack.stages
    )
    assert run(rest, '| savedsearch "Website Ping Runner Silent"') == []
    search = shipped_search("Website Ping Runner Silent")
    limit = 'relative_time(now(), "-10m")'
    assert limit in search
    rows = run(rest, "search " + search.replace(limit, 'relative_time(now(), "+1m")'))
    assert len(rows) == 1
    assert rows[0]["host"]
    assert rows[0]["last_heartbeat"]
