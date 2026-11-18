"""The event contract: one definition of what a website-ping event must contain."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

SOURCETYPE = "web_ping"
INDEX = "main"
TIME_SLACK = 60.0

ERROR_PATTERNS: dict[str, str] = {
    "Redirect limit": r"redirect limit",
    "ConnectionRefusedError": r"^ConnectionRefusedError: .*refused",
    "gaierror": r"^gaierror: ",
    "Expired certificate": r"^SSLCertVerificationError: .*certificate has expired",
    "Self-signed certificate": r"^SSLCertVerificationError: .*self[- ]signed certificate",
    "Wrong hostname": r"^SSLCertVerificationError: .*Hostname mismatch",
    "Unreachable network": r"^OSError: .*Network is unreachable",
    "TLS handshake failed": r"^SSLError: ",
    "ca_certs not readable": r"^ca_certs not readable: ",
}


@dataclass(frozen=True)
class Scenario:
    """One row of the scenario table. Stanza name and title are the same."""

    title: str
    url: str
    interval: int
    response_code: int | None
    """None: no complete response, the event has response_code="" and empty times."""
    timed_out: bool
    error: str | None = None
    """A key of ERROR_PATTERNS, or None for "absent"."""
    settings: Mapping[str, str] = field(default_factory=dict[str, str])
    requests: int | None = None
    max_duration: float | None = None
    """Seconds the check may take: total_time for a response, otherwise from the
    target's log of the check's request to the event's _time (the check's end)."""
    exceeded_redirects: bool = False
    has_expected_string: bool | None = None
    """The value expected with should_contain_string set; None: field absent."""
    body_event: bool = False
    """Whether a web_ping:response event comes with each check event."""

    @property
    def counted(self) -> bool:
        return self.interval == 3600


@dataclass(frozen=True)
class FieldDiff:
    field: str
    expected: str
    actual: str
    allowed: bool = False
    """A known, intended difference: reported, but it does not fail a test."""

    def __str__(self) -> str:
        text = f"{self.field}: expected {self.expected}, got {self.actual}"
        return text + " (allowed)" if self.allowed else text


def _number(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _duration(event: Mapping[str, str], request_times: Sequence[float]) -> float | None:
    """Seconds the check of this event took, or None if it cannot be told."""
    total_time = _number(event.get("total_time"))
    if total_time is not None:
        return total_time / 1000
    end = _number(event.get("wptest_time"))
    if end is None:
        return None
    starts = [start for start in request_times if start <= end]
    return end - max(starts) if starts else None


def compare(
    scenario: Scenario,
    events: list[dict[str, str]],
    *,
    host: str,
    mark: float,
    searched_at: float,
    requests: int | None = None,
    request_times: Sequence[float] = (),
    body_events: int | None = None,
) -> list[FieldDiff]:
    """Every field that differs from the contract, comparing the newest event.

    request_times are the target's log times of the scenario's requests, needed
    for max_duration when no response arrived. body_events is the number of the
    stanza's web_ping:response events since the mark (None: not counted)."""
    diffs: list[FieldDiff] = []
    if scenario.counted and len(events) != 1:
        diffs.append(FieldDiff("event count", "exactly 1", str(len(events))))
    if not events:
        return diffs + [FieldDiff("event", "at least 1", "none")]
    event = events[0]

    def expect(name: str, expected: str | None) -> None:
        actual = event.get(name)
        if actual != expected:
            diffs.append(
                FieldDiff(
                    name,
                    "absent" if expected is None else json.dumps(expected),
                    "absent" if actual is None else json.dumps(actual),
                )
            )

    expect("sourcetype", SOURCETYPE)
    expect("index", INDEX)
    expect("source", f"web_ping://{scenario.title}")
    expect("host", host)
    expect("title", scenario.title)
    expect("url", scenario.url)
    expect("timed_out", str(scenario.timed_out))
    expect("exceeded_redirects", "True" if scenario.exceeded_redirects else None)
    found = scenario.has_expected_string
    expect("has_expected_string", None if found is None else str(found).lower())

    if scenario.response_code is None:
        for name in ("response_code", "total_time", "request_time"):
            expect(name, "")
    else:
        expect("response_code", str(scenario.response_code))
        total_time = _number(event.get("total_time"))
        if total_time is None or total_time < 0:
            diffs.append(
                FieldDiff(
                    "total_time", "a non-negative number", str(event.get("total_time"))
                )
            )
        expect("request_time", event.get("total_time"))

    error = event.get("error")
    if scenario.error is None:
        expect("error", None)
    elif error is None or not re.search(ERROR_PATTERNS[scenario.error], error):
        diffs.append(
            FieldDiff(
                "error",
                f"{scenario.error} (/{ERROR_PATTERNS[scenario.error]}/)",
                "absent" if error is None else error,
            )
        )

    limit = scenario.max_duration
    if limit is not None:
        duration = _duration(event, request_times)
        if duration is None or duration > limit:
            diffs.append(
                FieldDiff(
                    "duration",
                    f"at most {limit:g} s",
                    "unknown" if duration is None else f"{duration:.1f} s",
                )
            )

    event_time = _number(event.get("wptest_time"))
    if event_time is None or not mark <= event_time <= searched_at + TIME_SLACK:
        diffs.append(
            FieldDiff(
                "_time",
                f"between {mark:.0f} and {searched_at + TIME_SLACK:.0f}",
                str(event.get("wptest_time")),
            )
        )

    if scenario.requests is not None and requests != scenario.requests:
        diffs.append(FieldDiff("requests", str(scenario.requests), str(requests)))
    if body_events is not None and (body_events > 0) != scenario.body_event:
        diffs.append(
            FieldDiff(
                "body event",
                "present" if scenario.body_event else "absent",
                f"{body_events} event(s)",
            )
        )
    return diffs


def describe(scenario: Scenario, diffs: list[FieldDiff]) -> str:
    lines = [f"{scenario.title}: {len(diffs)} field(s) differ from the contract"]
    lines += [f"  {diff}" for diff in diffs]
    return "\n".join(lines)
