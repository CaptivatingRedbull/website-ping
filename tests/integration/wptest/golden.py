"""Golden events of Website Monitoring 2.9.7: normalisation, storage and the diff.

Used by the capture (tests/integration/test_golden.py, --golden-write writes,
otherwise compares) and later by the website-ping parity tests.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Union, cast

from wptest.contract import FieldDiff
from wptest.parity import ParityScenario

FieldValue = Union[str, "list[str]"]
"""A search result value; a multivalue field is a list."""

CHECK_SOURCETYPE = "web_ping"
RESPONSE_SOURCETYPE = "web_ping:response"
NUMBER = "<number>"
VOLATILE = "<volatile>"
TIME = "<time>"
ARRIVAL_DAY = "<arrival day>"
TIME_FIELDS = frozenset({"total_time", "request_time"})
VOLATILE_HEADERS = frozenset(
    {"date", "server", "expires", "last-modified", "age", "etag", "via", "x-cache",
     "x-cache-lookup"}
)  # fmt: skip
NEAR_INDEX_TIME = 600.0
"""An event _time this close to _indextime was assigned at arrival, so it is volatile.
A _time further away was extracted from the event and is kept (see normalise_time)"""
ANY_FIELD = "*"

ALLOWED_DIFFERENCES: Mapping[str, Mapping[str, str]] = {
    # title -> {field -> reason}; "*" as title applies to every scenario,
    # "*" as field allows every field of that scenario.
    "*": {"error": "new in website-ping (additive)"},
    "slow-body": {ANY_FIELD: "timeout is a total deadline in website-ping"},
    "trickled-body": {ANY_FIELD: "timeout is a total deadline in website-ping"},
    "ntlm-offered": {ANY_FIELD: "NTLM not supported in website-ping"},
    # Content scenarios whose decoding relied on chardet: add after the capture,
    # one entry per title whose hashes differ without charset detection.
}

EXPORT_FIELDS = "wptest_raw wptest_time wptest_indextime wptest_cd wptest_server"
EXPORT_QUERY = (
    'search index=main (sourcetype=web_ping OR sourcetype="web_ping:response")'
    ' source="web_ping://*" _index_earliest={since}'
    " | eval wptest_raw=_raw, wptest_time=_time, wptest_indextime=_indextime,"
    " wptest_cd=_cd, wptest_server=splunk_server"
    " | sort 0 _time sourcetype"
    " | fields - _* date_* punct splunk_server* timestartpos timeendpos eventtype tag*"
    " | table *"
)


def export_query(since: float) -> str:
    return EXPORT_QUERY.format(since=int(since))


# ---- _raw ------------------------------------------------------------------

_PAIR = re.compile(r'(?P<key>[^\s=]+)=(?P<value>"(?:[^"\\]|\\.)*"|\S*)')


@dataclass(frozen=True)
class RawPair:
    key: str
    literal: str
    """The value as written in _raw, quotes and backslashes included."""

    @property
    def quoted(self) -> bool:
        return len(self.literal) >= 2 and self.literal[0] == self.literal[-1] == '"'


def parse_raw(raw: str) -> list[RawPair]:
    """key=value pairs of a check event, as 2.9.7's create_event_string writes them.

    Raises ValueError when something other than single spaces separates the pairs.
    """
    pairs: list[RawPair] = []
    position = 0
    while position < len(raw):
        if pairs:
            if raw[position] != " ":
                raise ValueError(f"no space before offset {position} in {raw!r}")
            position += 1
        match = _PAIR.match(raw, position)
        if match is None:
            raise ValueError(f"no key=value at offset {position} in {raw!r}")
        pairs.append(RawPair(match["key"], match["value"]))
        position = match.end()
    return pairs


def join_raw(pairs: Iterable[RawPair]) -> str:
    return " ".join(f"{pair.key}={pair.literal}" for pair in pairs)


# ---- Normalisation ---------------------------------------------------------


def _volatile_header(key: str) -> bool:
    return (
        key.startswith("header_") and key[len("header_") :].lower() in VOLATILE_HEADERS
    )


def _is_number(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def normalise_value(key: str, value: str) -> str:
    """One field value (unquoted). Empty strings stay as they are."""
    if key in TIME_FIELDS and _is_number(value):
        return NUMBER
    if _volatile_header(key) and value:
        return VOLATILE
    return value


def normalise_literal(key: str, literal: str) -> str:
    """One value as written in _raw, keeping its quotes."""
    quoted = len(literal) >= 2 and literal[0] == literal[-1] == '"'
    inner = literal[1:-1] if quoted else literal
    normalised = normalise_value(key, inner)
    if normalised == inner:
        return literal
    return f'"{normalised}"' if quoted else normalised


def normalise_raw(raw: str, sourcetype: str) -> str:
    if sourcetype != CHECK_SOURCETYPE:
        return raw
    pairs = parse_raw(raw)
    return join_raw(RawPair(p.key, normalise_literal(p.key, p.literal)) for p in pairs)


def normalise_time(event_time: str, index_time: str) -> str:
    """TIME for a _time assigned at arrival. A _time Splunk took from the event
    text is kept as UTC ISO 8601; when it falls on the day of arrival (Splunk
    took only the time of day), the date is ARRIVAL_DAY so the fixture does
    not depend on the day of the capture."""
    try:
        event, index = float(event_time), float(index_time)
    except ValueError:
        return event_time
    if abs(event - index) <= NEAR_INDEX_TIME:
        return TIME
    parsed = time.gmtime(event)
    text = time.strftime("%Y-%m-%dT%H:%M:%SZ", parsed)
    if parsed[:3] == time.gmtime(index)[:3]:
        return ARRIVAL_DAY + text[10:]
    return text


# ---- Events ----------------------------------------------------------------


@dataclass(frozen=True)
class GoldenEvent:
    """One event, normalised. fields holds the search-time and index fields,
    including source, sourcetype, host, index, linecount and _time."""

    raw: str
    fields: Mapping[str, FieldValue]

    @property
    def sourcetype(self) -> str:
        return _single(self.fields.get("sourcetype", ""))

    @property
    def source(self) -> str:
        return _single(self.fields.get("source", ""))


def _single(value: FieldValue) -> str:
    return value if isinstance(value, str) else (value[0] if value else "")


def _normalise_field(key: str, value: FieldValue) -> FieldValue:
    if isinstance(value, str):
        return normalise_value(key, value)
    return [normalise_value(key, item) for item in value]


def event_from_result(result: Mapping[str, FieldValue]) -> GoldenEvent:
    """A row of the export query, normalised."""
    raw = _single(result.get("wptest_raw", ""))
    sourcetype = _single(result.get("sourcetype", ""))
    fields: dict[str, FieldValue] = {
        key: _normalise_field(key, value)
        for key, value in result.items()
        if key not in EXPORT_FIELDS.split()
    }
    fields["_time"] = normalise_time(
        _single(result.get("wptest_time", "")),
        _single(result.get("wptest_indextime", "")),
    )
    return GoldenEvent(normalise_raw(raw, sourcetype), dict(sorted(fields.items())))


def parse_export(text: str) -> list[dict[str, FieldValue]]:
    """JSON lines of /search/jobs/export, keeping multivalue fields as lists."""
    results: list[dict[str, FieldValue]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        entry = cast("dict[str, object]", json.loads(line))
        if entry.get("preview") is True:
            continue  # partial results streamed before the final ones
        result = entry.get("result")
        if not isinstance(result, dict):
            continue
        row: dict[str, FieldValue] = {}
        for key, value in cast("dict[str, object]", result).items():
            if isinstance(value, list):
                row[key] = [str(item) for item in cast("list[object]", value)]
            else:
                row[key] = str(value)
        results.append(row)
    return results


def event_time(result: Mapping[str, FieldValue]) -> float:
    return float(_single(result.get("wptest_time", "0")))


def arrival_time(result: Mapping[str, FieldValue]) -> float:
    """_indextime: when the event arrived. Unlike _time it cannot come from a date
    in the event text, so it orders the checks of one stanza."""
    return float(_single(result.get("wptest_indextime", "0")))


def arrival_order(result: Mapping[str, FieldValue]) -> tuple[float, float]:
    return arrival_time(result), event_time(result)


# ---- Request logs ----------------------------------------------------------


@dataclass(frozen=True)
class TargetRequest:
    port: int
    method: str
    path: str
    user_agent: str
    authorization: str
    status: int
    client_cn: str = ""
    host: str = ""
    accept: str = ""
    accept_encoding: str = ""
    connection: str = ""
    cookie: str = ""
    """Cookie names only."""
    header_names: tuple[str, ...] = ()
    """Request header names in the order received."""
    request_line: str = ""
    """Latin-1 decoded; only for the path route and rejected requests."""
    rejected: bool = False
    """The target's HTTP parser refused the request line (status 400)."""


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    url: str
    result: str
    """Squid's %Ss/%03>Hs, such as TCP_MISS/200."""
    user: str
    user_agent: str


def target_request(record: Mapping[str, object]) -> TargetRequest:
    return TargetRequest(
        port=int(str(record.get("port", 0))),
        method=str(record.get("method", "")),
        path=str(record.get("path", "")),
        user_agent=str(record.get("user_agent", "")),
        authorization=str(record.get("authorization", "")),
        status=int(str(record.get("status", 0))),
        client_cn=str(record.get("client_cn", "")),
        host=str(record.get("host", "")),
        accept=str(record.get("accept", "")),
        accept_encoding=str(record.get("accept_encoding", "")),
        connection=str(record.get("connection", "")),
        cookie=str(record.get("cookie", "")),
        header_names=tuple(
            str(name) for name in cast("list[object]", record.get("header_names", []))
        ),
        request_line=str(record.get("request_line", "")),
        rejected=record.get("rejected") is True,
    )


_SQUID = re.compile(
    r"^(?P<time>\d+\.\d+) \S+ port=\d+ (?P<result>\S+) (?P<method>\S+)"
    r' (?P<url>\S+) user=(?P<user>\S*) ua="(?P<ua>.*)"$'
)


def parse_squid_line(line: str) -> tuple[float, ProxyRequest] | None:
    """A line of the wptest log format in squid.conf, or None for anything else."""
    match = _SQUID.match(line.strip())
    if match is None:
        return None
    return float(match["time"]), ProxyRequest(
        match["method"], match["url"], match["result"], match["user"], match["ua"]
    )


# ---- Captures --------------------------------------------------------------


@dataclass(frozen=True)
class Capture:
    """Everything stored for one scenario."""

    title: str
    complete: bool
    """False when fewer check events than min_events arrived before the deadline."""
    events: tuple[GoldenEvent, ...]
    requests: tuple[TargetRequest, ...]
    proxy_requests: tuple[ProxyRequest, ...]


REQUEST_SLACK = 1.0
"""Seconds after the last kept event's arrival in which its requests may be logged.
The next check of the same stanza starts an interval (at least 60 s) later."""


def select_capture(
    scenario: ParityScenario,
    results: Sequence[Mapping[str, FieldValue]],
    target_log: Sequence[Mapping[str, object]],
    squid_log: Sequence[tuple[float, ProxyRequest]],
    since: float,
) -> Capture:
    """The first min_events checks of one scenario, with their body events and
    the requests made for them.

    results are the export rows of the scenario's source in arrival order
    (arrival_order). The requests kept are those logged between since and the
    arrival of the last kept event (plus REQUEST_SLACK), so later checks during
    the wait do not count. Arrival, not _time, bounds the window: an event whose
    _time Splunk took from its text would otherwise end it years early. With no
    event at all, every request since the mark is kept, to show what happened.
    """
    checks = [
        r for r in results if _single(r.get("sourcetype", "")) == CHECK_SOURCETYPE
    ]
    kept = checks[: scenario.min_events]
    until = arrival_time(kept[-1]) + REQUEST_SLACK if kept else math.inf
    events = [r for r in results if arrival_time(r) <= until]
    requests = [
        target_request(record)
        for record in target_log
        if since <= float(str(record.get("time", 0))) <= until
        and scenario.matches_request(
            int(str(record.get("port", 0))), str(record.get("path", ""))
        )
    ]
    proxied = [
        request
        for logged, request in squid_log
        if since <= logged <= until and scenario.matches_proxy(request.url)
    ]
    return Capture(
        scenario.title,
        len(kept) >= scenario.min_events,
        tuple(event_from_result(r) for r in events),
        tuple(requests),
        tuple(proxied),
    )


def to_json(capture: Capture) -> dict[str, object]:
    return {
        "title": capture.title,
        "complete": capture.complete,
        "events": [{"_raw": e.raw, "fields": dict(e.fields)} for e in capture.events],
        "requests": [vars(r) for r in capture.requests],
        "proxy_requests": [vars(r) for r in capture.proxy_requests],
    }


def from_json(data: Mapping[str, object]) -> Capture:
    events = cast("list[dict[str, object]]", data["events"])
    requests = cast("list[dict[str, object]]", data["requests"])
    proxied = cast("list[dict[str, str]]", data["proxy_requests"])
    return Capture(
        title=str(data["title"]),
        complete=bool(data["complete"]),
        events=tuple(
            GoldenEvent(str(e["_raw"]), cast("dict[str, FieldValue]", e["fields"]))
            for e in events
        ),
        requests=tuple(target_request(r) for r in requests),
        proxy_requests=tuple(ProxyRequest(**p) for p in proxied),
    )


def write_capture(folder: Path, capture: Capture) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{capture.title}.json"
    text = json.dumps(to_json(capture), indent=2, sort_keys=True, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def read_capture(folder: Path, title: str) -> Capture:
    text = (folder / f"{title}.json").read_text(encoding="utf-8")
    return from_json(cast("dict[str, object]", json.loads(text)))


# ---- Diff ------------------------------------------------------------------


def allowed_fields(title: str) -> dict[str, str]:
    """Field -> reason for the differences allowed on one scenario."""
    return {**ALLOWED_DIFFERENCES.get("*", {}), **ALLOWED_DIFFERENCES.get(title, {})}


def _show(value: FieldValue | None) -> str:
    if value is None:
        return "absent"
    return json.dumps(value, ensure_ascii=False)


def compare(
    golden: GoldenEvent, actual: GoldenEvent, allowed: Collection[str] = ()
) -> list[FieldDiff]:
    """Every difference between two normalised events: sourcetype, source, the
    field set and values, and for check events the order of the fields in _raw
    and how each value is quoted. Differences on allowed fields (or on any field
    when allowed holds "*") are returned with allowed=True."""
    diffs: list[FieldDiff] = []
    for name in ("sourcetype", "source"):
        if golden.fields.get(name) != actual.fields.get(name):
            diffs.append(
                FieldDiff(
                    name, _show(golden.fields.get(name)), _show(actual.fields.get(name))
                )
            )
    for name in sorted(golden.fields.keys() | actual.fields.keys()):
        if name in ("sourcetype", "source"):
            continue
        expected, got = golden.fields.get(name), actual.fields.get(name)
        if expected != got:
            diffs.append(FieldDiff(name, _show(expected), _show(got)))
    if golden.sourcetype != CHECK_SOURCETYPE or actual.sourcetype != CHECK_SOURCETYPE:
        if golden.raw != actual.raw:
            diffs.append(FieldDiff("_raw", _show(golden.raw), _show(actual.raw)))
    else:
        diffs += _compare_raw(golden.raw, actual.raw)
    return [_mark(diff, allowed) for diff in diffs]


def _mark(diff: FieldDiff, allowed: Collection[str]) -> FieldDiff:
    if ANY_FIELD in allowed or diff_field(diff) in allowed:
        return FieldDiff(diff.field, diff.expected, diff.actual, allowed=True)
    return diff


def _compare_raw(golden: str, actual: str) -> list[FieldDiff]:
    try:
        expected_pairs, actual_pairs = parse_raw(golden), parse_raw(actual)
    except ValueError as exc:
        return [FieldDiff("_raw", "key=value pairs", str(exc))]
    diffs: list[FieldDiff] = []
    expected_keys = [p.key for p in expected_pairs]
    actual_keys = [p.key for p in actual_pairs]
    common = set(expected_keys) & set(actual_keys)
    in_golden = [k for k in expected_keys if k in common]
    in_actual = [k for k in actual_keys if k in common]
    if in_golden != in_actual:
        diffs.append(FieldDiff("_raw order", " ".join(in_golden), " ".join(in_actual)))
    for key in sorted(set(expected_keys) ^ set(actual_keys)):
        diffs.append(
            FieldDiff(
                f"_raw:{key}",
                "present" if key in expected_keys else "absent",
                "present" if key in actual_keys else "absent",
            )
        )
    literals_expected = {p.key: p.literal for p in expected_pairs}
    literals_actual = {p.key: p.literal for p in actual_pairs}
    for key in sorted(common):
        if literals_expected[key] != literals_actual[key]:
            diffs.append(
                FieldDiff(f"_raw:{key}", literals_expected[key], literals_actual[key])
            )
    return diffs


def diff_field(diff: FieldDiff) -> str:
    """The event field a difference is about: "_raw:error" is about error.
    "_raw order" is about no single field, so only "*" allows it (fields added by
    website-ping do not change the order of the common fields)."""
    return diff.field.split(":", 1)[1] if diff.field.startswith("_raw:") else diff.field


def failing(diffs: Sequence[FieldDiff]) -> list[FieldDiff]:
    return [diff for diff in diffs if not diff.allowed]


def compare_capture(golden: Capture, actual: Capture) -> list[FieldDiff]:
    """Event by event, then the request logs. Event fields are prefixed with the
    event's position, such as "event 0: total_time"."""
    diffs: list[FieldDiff] = []
    if golden.complete != actual.complete:
        diffs.append(FieldDiff("complete", str(golden.complete), str(actual.complete)))
    if len(golden.events) != len(actual.events):
        diffs.append(
            FieldDiff("event count", str(len(golden.events)), str(len(actual.events)))
        )
    for index, (expected, got) in enumerate(zip(golden.events, actual.events)):
        diffs += [
            FieldDiff(f"event {index}: {d.field}", d.expected, d.actual, d.allowed)
            for d in compare(expected, got)
        ]
    for name, expected_log, actual_log in (
        ("requests", golden.requests, actual.requests),
        ("proxy requests", golden.proxy_requests, actual.proxy_requests),
    ):
        if expected_log != actual_log:
            diffs.append(
                FieldDiff(
                    name,
                    json.dumps([vars(r) for r in expected_log]),
                    json.dumps([vars(r) for r in actual_log]),
                )
            )
    return diffs
