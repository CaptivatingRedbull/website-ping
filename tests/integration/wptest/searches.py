"""Search-time behaviour of Website Monitoring 2.9.7, recorded next to the golden
events in _searches.json: how empty values behave in searches, what the shipped
alert and range-map searches return, and how Splunk timed and broke events
whose text holds a date or several lines.

Each search runs in the old app's namespace, so its macros, tags and saved
searches apply. Values that change between captures are replaced by
VOLATILE, so a fresh recording can be compared with the stored one.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from wptest.golden import (
    REQUEST_SLACK,
    FieldValue,
    arrival_order,
    arrival_time,
    normalise_raw,
    normalise_time,
)

FILE_NAME = "_searches.json"
VOLATILE = "<volatile>"
ALERT_TITLES = ("status-200", "status-503", "refused", "timeout", "match-no")
"""status-200 is the control: a healthy site the searches must not report."""
TIMED_SOURCES = ("date-in-url", "date-in-title", "body-lines")

_TITLES = "(" + " OR ".join(f"title={title}" for title in ALERT_TITLES) + ")"
_BASE = "search index=main sourcetype=web_ping _index_earliest={since}"


@dataclass(frozen=True)
class RecordedSearch:
    name: str
    question: str
    query: str
    """{since} is replaced with the epoch second of the capture's mark."""
    volatile: frozenset[str] = field(default_factory=lambda: frozenset[str]())
    """Fields whose values depend on how long the capture ran."""
    first_check_only: bool = False
    """Keep, per source, only the events of the first check (by arrival)."""
    only_titles: frozenset[str] = field(default_factory=lambda: frozenset[str]())
    """When set, keep only rows of these titles. Other rows can depend on the
    response time of a check (a slow healthy site is reported too)."""


COUNT = frozenset({"count"})

SEARCHES: tuple[RecordedSearch, ...] = (
    RecordedSearch(
        "empty-fields",
        'Are the empty values of a failed check (response_code="") null at search time?',
        f"{_BASE} title=refused"
        ' | eval response_code_is=if(isnull(response_code),"null","set"),'
        ' total_time_is=if(isnull(total_time),"null","set"),'
        ' proxy_port_is=if(isnull(proxy_port),"null","set")'
        " | stats count by response_code_is total_time_is proxy_port_is",
        COUNT,
    ),
    RecordedSearch(
        "match-empty-response-code",
        'Which titles does response_code="" match?',
        f'{_BASE} {_TITLES} response_code="" | stats count by title',
        COUNT,
    ),
    RecordedSearch(
        "match-no-response-code",
        'Which titles does NOT response_code="*" match?',
        f'{_BASE} {_TITLES} NOT response_code="*" | stats count by title',
        COUNT,
    ),
    RecordedSearch(
        "match-tag-not-equal",
        'Which titles does tag!="exclude_from_alerts" keep (no event has a tag)?',
        f'{_BASE} {_TITLES} tag!="exclude_from_alerts" | stats count by title',
        COUNT,
    ),
    RecordedSearch(
        "match-not-tag",
        'Which titles does NOT tag="exclude_from_alerts" keep?',
        f'{_BASE} {_TITLES} NOT tag="exclude_from_alerts" | stats count by title',
        COUNT,
    ),
    RecordedSearch(
        "alert",
        "Rows of the shipped alert Website Performance Problem.",
        '| savedsearch "Website Performance Problem"',
        frozenset({"count", "max_total_time"}),
        only_titles=frozenset(ALERT_TITLES),
    ),
    RecordedSearch(
        "inoperable-rangemap",
        "Result of the shipped search inoperable_sites_rangemap.",
        "| savedsearch inoperable_sites_rangemap",
    ),
    RecordedSearch(
        "inoperable-by-site",
        "Which sites inoperable_sites_rangemap counts as down (its search up to"
        " the eval of down, per site).",
        'search sourcetype="web_ping" `website_monitoring_search_index`'
        " _index_earliest={since}"
        " | stats latest(title) as title latest(response_code) as response_code"
        " latest(timed_out) as timed_out distinct_count(url) as count by url"
        ' | eval down=if(response_code>=400,1,if(timed_out=="True", 1, 0))'
        " | table title response_code timed_out down",
    ),
    RecordedSearch(
        "event-times",
        "For events whose text holds a date or several lines: _time against"
        " arrival, linecount, the timestamp field and the number of events of"
        " one check.",
        'search index=main (sourcetype=web_ping OR sourcetype="web_ping:response")'
        " ("
        + " OR ".join(f'source="web_ping://{name}"' for name in TIMED_SOURCES)
        + ") _index_earliest={since}"
        " | eval wptest_time=_time, wptest_indextime=_indextime, wptest_raw=_raw"
        " | table source sourcetype wptest_time wptest_indextime linecount"
        " timestamp wptest_raw",
        first_check_only=True,
    ),
)

Row = Mapping[str, FieldValue]


def first_check(rows: Sequence[Row]) -> list[Row]:
    """Per source, the events that arrived with its first check event."""
    kept: list[Row] = []
    by_source: dict[str, list[Row]] = {}
    for row in rows:
        by_source.setdefault(str(row.get("source", "")), []).append(row)
    for source in sorted(by_source):
        events = sorted(by_source[source], key=arrival_order)
        checks = [e for e in events if e.get("sourcetype") == "web_ping"]
        if not checks:
            kept += events
            continue
        until = arrival_time(checks[0]) + REQUEST_SLACK
        kept += [e for e in events if arrival_time(e) <= until]
    return kept


def _str(value: FieldValue | None) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else ",".join(value)


def normalise_rows(
    search: RecordedSearch, rows: Sequence[Row]
) -> list[dict[str, FieldValue]]:
    """Volatile fields replaced; _time and _raw normalised as in the event
    fixtures (golden.normalise_time, golden.normalise_raw); rows sorted, unless
    they are events in arrival order."""
    if search.first_check_only:
        rows = first_check(rows)
    if search.only_titles:
        rows = [r for r in rows if _str(r.get("title")) in search.only_titles]
    result: list[dict[str, FieldValue]] = []
    for row in rows:
        values: dict[str, FieldValue] = {}
        for key, value in row.items():
            if key in search.volatile:
                values[key] = VOLATILE
            elif key == "wptest_indextime":
                continue
            elif key == "wptest_time":
                values["_time"] = normalise_time(
                    _str(value), _str(row.get("wptest_indextime"))
                )
            elif key == "wptest_raw":
                values["_raw"] = normalise_raw(_str(value), _str(row.get("sourcetype")))
            else:
                values[key] = value
        result.append(dict(sorted(values.items())))
    if search.first_check_only:
        return result
    return sorted(result, key=lambda r: json.dumps(r, sort_keys=True))


def record(search: RecordedSearch, rows: Sequence[Row], app: str) -> dict[str, object]:
    return {
        "name": search.name,
        "question": search.question,
        "app": app,
        "query": search.query,
        "rows": normalise_rows(search, rows),
    }


def write(folder: Path, recorded: Sequence[Mapping[str, object]]) -> Path:
    path = folder / FILE_NAME
    text = json.dumps(
        {"searches": list(recorded)}, indent=2, sort_keys=True, ensure_ascii=False
    )
    path.write_text(text + "\n", encoding="utf-8")
    return path


def read(folder: Path) -> dict[str, dict[str, object]]:
    data = cast(
        "dict[str, list[dict[str, object]]]",
        json.loads((folder / FILE_NAME).read_text(encoding="utf-8")),
    )
    return {str(entry["name"]): entry for entry in data["searches"]}


def differences(
    stored: Mapping[str, Mapping[str, object]],
    fresh: Sequence[Mapping[str, object]],
) -> list[str]:
    """One line per search whose rows or query differ, or that only one side has."""
    problems: list[str] = []
    fresh_by_name = {str(entry["name"]): entry for entry in fresh}
    for name in sorted(stored.keys() | fresh_by_name.keys()):
        old, new = stored.get(name), fresh_by_name.get(name)
        if old is None or new is None:
            problems.append(f"{name}: only in {'stored' if new is None else 'fresh'}")
        elif old["query"] != new["query"] or old["rows"] != new["rows"]:
            problems.append(
                f"{name}: stored {json.dumps(old['rows'], ensure_ascii=False)}"
                f" fresh {json.dumps(new['rows'], ensure_ascii=False)}"
            )
    return problems
