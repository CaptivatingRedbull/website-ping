"""The event contract: one definition of what a website-ping event must contain."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

SOURCETYPE = "website-ping"
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
}


@dataclass(frozen=True)
class Scenario:
    """One row of the scenario table. Stanza name and title are the same."""

    title: str
    url: str
    interval: int
    response_code: int
    timed_out: int
    error: str | None = None
    """A key of ERROR_PATTERNS, or None for "absent"."""
    settings: Mapping[str, str] = field(default_factory=dict[str, str])
    requests: int | None = None
    max_total_time: float | None = None

    @property
    def counted(self) -> bool:
        return self.interval == 3600


@dataclass(frozen=True)
class FieldDiff:
    field: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return f"{self.field}: expected {self.expected}, got {self.actual}"


def _number(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def compare(
    scenario: Scenario,
    events: list[dict[str, str]],
    *,
    host: str,
    mark: float,
    searched_at: float,
    requests: int | None = None,
) -> list[FieldDiff]:
    """Every field that differs from the contract, comparing the newest event."""
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
                    "absent" if expected is None else expected,
                    "absent" if actual is None else actual,
                )
            )

    expect("sourcetype", SOURCETYPE)
    expect("index", INDEX)
    expect("source", f"web_ping://{scenario.title}")
    expect("host", host)
    expect("title", scenario.title)
    expect("url", scenario.url)
    expect("response_code", str(scenario.response_code))
    expect("timed_out", str(scenario.timed_out))

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

    total_time = _number(event.get("total_time"))
    limit = scenario.max_total_time
    if (
        total_time is None
        or total_time < 0
        or (limit is not None and total_time > limit)
    ):
        expected = (
            f"at most {limit:g}" if limit is not None else "a non-negative number"
        )
        diffs.append(FieldDiff("total_time", expected, str(event.get("total_time"))))

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
    return diffs


def describe(scenario: Scenario, diffs: list[FieldDiff]) -> str:
    lines = [f"{scenario.title}: {len(diffs)} field(s) differ from the contract"]
    lines += [f"  {diff}" for diff in diffs]
    return "\n".join(lines)
