"""Recorded searches of Website Monitoring 2.9.7 (wptest/searches.py)."""

from __future__ import annotations

from pathlib import Path

from wptest import golden, parity, searches
from wptest.searches import SEARCHES, RecordedSearch


def by_name(name: str) -> RecordedSearch:
    return next(search for search in SEARCHES if search.name == name)


def test_queries_format_and_name_existing_scenarios() -> None:
    titles = set(parity.by_title())
    assert set(searches.ALERT_TITLES) <= titles
    assert set(searches.TIMED_SOURCES) <= titles
    names = [search.name for search in SEARCHES]
    assert len(names) == len(set(names))
    for search in SEARCHES:
        query = search.query.format(since=1700000000)
        assert query.startswith(("search ", "| ")), search.name
        assert "{" not in query, search.name


def test_counts_are_volatile_but_presence_is_kept() -> None:
    rows: list[searches.Row] = [
        {"title": "timeout", "count": "7"},
        {"title": "refused", "count": "3"},
    ]
    assert searches.normalise_rows(by_name("match-empty-response-code"), rows) == [
        {"count": searches.VOLATILE, "title": "refused"},
        {"count": searches.VOLATILE, "title": "timeout"},
    ]


def test_rangemap_count_is_kept() -> None:
    rows: list[searches.Row] = [{"count": "4", "range": "severe"}]
    assert searches.normalise_rows(by_name("inoperable-rangemap"), rows) == [
        {"count": "4", "range": "severe"}
    ]


def event(source: str, sourcetype: str, time: float, indextime: float) -> searches.Row:
    return {
        "source": f"web_ping://{source}",
        "sourcetype": sourcetype,
        "wptest_time": str(time),
        "wptest_indextime": str(indextime),
        "wptest_raw": "response_code=200 total_time=4.3 title=x",
        "linecount": "1",
    }


def test_event_times_keep_the_first_check_and_text_dates() -> None:
    rows = [
        event("body-lines", "web_ping:response", 1000.0, 1000.0),
        event("body-lines", "web_ping:response", 4000.0, 1000.0),
        event("body-lines", "web_ping", 1000.0, 1000.0),
        event("body-lines", "web_ping", 1060.0, 1060.0),
        event("date-in-url", "web_ping", 1577934245.0, 100001.0),
        event("date-in-url", "web_ping", 1577934245.0, 100061.0),
    ]
    result = searches.normalise_rows(by_name("event-times"), rows)
    assert [(r["source"], r["sourcetype"], r["_time"]) for r in result] == [
        ("web_ping://body-lines", "web_ping:response", golden.TIME),
        ("web_ping://body-lines", "web_ping", golden.TIME),
        ("web_ping://body-lines", "web_ping:response", "<arrival day>T01:06:40Z"),
        ("web_ping://date-in-url", "web_ping", "2020-01-02T03:04:05Z"),
    ]
    assert all("wptest_indextime" not in r for r in result)
    check = next(r for r in result if r["sourcetype"] == "web_ping")
    assert check["_raw"] == "response_code=200 total_time=<number> title=x"
    body = next(r for r in result if r["sourcetype"] == "web_ping:response")
    assert body["_raw"] == "response_code=200 total_time=4.3 title=x"


def test_round_trip_and_differences(tmp_path: Path) -> None:
    search = by_name("inoperable-rangemap")
    recorded = [searches.record(search, [{"count": "4"}], "website_monitoring")]
    searches.write(tmp_path, recorded)
    stored = searches.read(tmp_path)
    assert searches.differences(stored, recorded) == []
    changed = [searches.record(search, [{"count": "5"}], "website_monitoring")]
    assert [line.split(":")[0] for line in searches.differences(stored, changed)] == [
        "inoperable-rangemap"
    ]
    assert searches.differences(stored, []) == ["inoperable-rangemap: only in stored"]


def test_alert_keeps_only_the_titles_it_is_recorded_for() -> None:
    rows: list[searches.Row] = [
        {"title": "refused", "description": "Connection failed", "count": "2"},
        {"title": "cookie-redirect", "description": "200 (OK)", "count": "1"},
    ]
    assert searches.normalise_rows(by_name("alert"), rows) == [
        {"count": searches.VOLATILE, "description": "Connection failed",
         "title": "refused"}
    ]  # fmt: skip
