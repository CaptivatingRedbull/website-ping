"""The event contract of the integration tests (wptest/contract.py)."""

from __future__ import annotations

from collections.abc import Sequence

from wptest.contract import FieldDiff, Scenario, compare

MARK = 1000.0
URL = "http://target:8080/x"


def event(**fields: str) -> dict[str, str]:
    base = {
        "sourcetype": "web_ping",
        "index": "main",
        "source": "web_ping://t",
        "host": "so1",
        "title": "t",
        "url": URL,
        "timed_out": "False",
        "wptest_time": "1010.0",
    }
    return {**base, **fields}


def answered(**fields: str) -> dict[str, str]:
    times = {"response_code": "200", "total_time": "12.5", "request_time": "12.5"}
    return event(**{**times, **fields})


def unanswered(**fields: str) -> dict[str, str]:
    return event(
        **{"response_code": "", "total_time": "", "request_time": "", **fields}
    )


def fields_of(diffs: list[FieldDiff]) -> list[str]:
    return [diff.field for diff in diffs]


def run(
    scenario: Scenario, found: dict[str, str], request_times: Sequence[float] = ()
) -> list[FieldDiff]:
    return compare(
        scenario,
        [found],
        host="so1",
        mark=MARK,
        searched_at=1020.0,
        request_times=request_times,
    )


def test_answered_event_passes() -> None:
    assert run(Scenario("t", URL, 15, 200, False), answered()) == []


def test_wrong_code_and_mismatched_times_are_reported() -> None:
    diffs = run(
        Scenario("t", URL, 15, 200, False),
        answered(response_code="302", request_time="1"),
    )
    assert fields_of(diffs) == ["response_code", "request_time"]


def test_no_response_expects_empty_code_and_times() -> None:
    scenario = Scenario("t", URL, 15, None, True, max_duration=7)
    assert run(scenario, unanswered(timed_out="True"), request_times=[1004.0]) == []
    diffs = run(scenario, answered(timed_out="True"), request_times=[1004.0])
    assert fields_of(diffs) == ["response_code", "total_time", "request_time"]
    assert diffs[0].expected == '""' and diffs[0].actual == '"200"'


def test_timed_out_is_compared_as_python_bool() -> None:
    diffs = run(Scenario("t", URL, 15, None, True), unanswered())
    assert [(d.field, d.expected, d.actual) for d in diffs] == [
        ("timed_out", '"True"', '"False"')
    ]


def test_exceeded_redirects_expected_or_absent() -> None:
    limited = Scenario("t", URL, 15, None, False, exceeded_redirects=True)
    assert run(limited, unanswered(exceeded_redirects="True")) == []
    assert fields_of(run(limited, unanswered())) == ["exceeded_redirects"]
    plain = Scenario("t", URL, 15, 200, False)
    assert fields_of(run(plain, answered(exceeded_redirects="True"))) == [
        "exceeded_redirects"
    ]


def test_duration_of_an_answered_check_is_total_time() -> None:
    scenario = Scenario("t", URL, 15, 200, False, max_duration=7)
    assert run(scenario, answered(total_time="6999", request_time="6999")) == []
    diffs = run(scenario, answered(total_time="16000", request_time="16000"))
    assert [(d.field, d.actual) for d in diffs] == [("duration", "16.0 s")]


def test_duration_without_response_runs_from_the_check_request() -> None:
    scenario = Scenario("t", URL, 15, None, True, max_duration=7)
    found = unanswered(timed_out="True", wptest_time="1020.0")
    # The latest request at or before the event's end belongs to this check.
    assert run(scenario, found, request_times=[990.0, 1014.0, 1030.0]) == []
    diffs = run(scenario, found, request_times=[1004.0])
    assert [(d.field, d.actual) for d in diffs] == [("duration", "16.0 s")]
    diffs = run(scenario, found, request_times=[])
    assert [(d.field, d.actual) for d in diffs] == [("duration", "unknown")]
