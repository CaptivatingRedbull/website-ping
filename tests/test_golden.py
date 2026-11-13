"""Normalisation, storage and the diff of golden events (wptest/golden.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from wptest import golden
from wptest.golden import GoldenEvent, ProxyRequest, RawPair
from wptest.parity import ParityScenario

CHECK = "web_ping"
RESPONSE = "web_ping:response"


def event(raw: str, sourcetype: str = CHECK, **fields: str) -> GoldenEvent:
    values: dict[str, golden.FieldValue] = {
        "sourcetype": sourcetype,
        "source": "web_ping://t",
        **fields,
    }
    return GoldenEvent(raw, values)


# ---- _raw ------------------------------------------------------------------


def test_parse_raw_reads_quoted_and_plain_values() -> None:
    raw = 'response_code=200 title="He said \\"hi\\" it\\\'s" timeout=5 total_time=""'
    assert golden.parse_raw(raw) == [
        RawPair("response_code", "200"),
        RawPair("title", '"He said \\"hi\\" it\\\'s"'),
        RawPair("timeout", "5"),
        RawPair("total_time", '""'),
    ]
    assert golden.join_raw(golden.parse_raw(raw)) == raw


def test_parse_raw_quoted_flag() -> None:
    pairs = golden.parse_raw('a="x y" b=z')
    assert [p.quoted for p in pairs] == [True, False]


@pytest.mark.parametrize("raw", ["a=1  b=2", "a=1 junk", " a=1"])
def test_parse_raw_rejects_other_layouts(raw: str) -> None:
    with pytest.raises(ValueError):
        golden.parse_raw(raw)


# ---- Normalisation ---------------------------------------------------------


def test_normalise_raw_replaces_times_and_volatile_headers() -> None:
    raw = (
        "response_code=200 total_time=12.5 request_time=12.5 timed_out=False"
        ' header_Date="Thu, 12 Nov 2026 14:00:00 GMT" header_X-Wptest=one'
    )
    assert golden.normalise_raw(raw, CHECK) == (
        "response_code=200 total_time=<number> request_time=<number> timed_out=False"
        ' header_Date="<volatile>" header_X-Wptest=one'
    )


def test_normalise_raw_keeps_empty_times_and_response_bodies() -> None:
    assert golden.normalise_raw('total_time="" request_time=""', CHECK) == (
        'total_time="" request_time=""'
    )
    assert golden.normalise_raw("total_time=1.5 anything", RESPONSE) == (
        "total_time=1.5 anything"
    )


def test_normalise_time() -> None:
    assert golden.normalise_time("1000.5", "1001") == golden.TIME
    assert golden.normalise_time("315532800", "1763000000") == "1980-01-01T00:00:00Z"
    # 2026-11-13T03:04:05Z, arrived 2026-11-13T05:06:40Z: only the time of day
    assert (
        golden.normalise_time("1794539045", "1794546400") == "<arrival day>T03:04:05Z"
    )
    assert golden.normalise_time("x", "1") == "x"


def test_event_from_result_normalises_fields() -> None:
    result: dict[str, golden.FieldValue] = {
        "wptest_raw": "response_code=200 total_time=0.12",
        "wptest_time": "1000.25",
        "wptest_indextime": "1001",
        "sourcetype": CHECK,
        "source": "web_ping://status-200",
        "host": "so1",
        "total_time": "0.12",
        "header_Server": "wptest-target Python/3.13.18",
        "header_Set-Cookie": ["a=1", "b=2"],
    }
    item = golden.event_from_result(result)
    assert item.raw == "response_code=200 total_time=<number>"
    assert item.fields == {
        "_time": golden.TIME,
        "header_Server": golden.VOLATILE,
        "header_Set-Cookie": ["a=1", "b=2"],
        "host": "so1",
        "source": "web_ping://status-200",
        "sourcetype": CHECK,
        "total_time": golden.NUMBER,
    }


def test_parse_export_keeps_multivalue_fields() -> None:
    text = "\n".join(
        json.dumps(line)
        for line in (
            {"preview": True, "result": {"a": "partial"}},
            {"preview": False, "result": {"a": "1", "b": ["x", "y"]}},
            {"preview": False, "lastrow": True},
        )
    )
    assert golden.parse_export(text) == [{"a": "1", "b": ["x", "y"]}]


def test_parse_squid_line() -> None:
    line = (
        "1763000000.123 172.18.0.4 port=3129 TCP_MISS/200 GET"
        ' http://target:8080/done/proxy-auth user=wpproxy ua="Splunk Website Monitoring"'
    )
    assert golden.parse_squid_line(line) == (
        1763000000.123,
        ProxyRequest(
            "GET",
            "http://target:8080/done/proxy-auth",
            "TCP_MISS/200",
            "wpproxy",
            "Splunk Website Monitoring",
        ),
    )
    assert golden.parse_squid_line("2026/11/12 cache.log line") is None


# ---- Diff ------------------------------------------------------------------


def test_compare_same_event_is_empty() -> None:
    one = event("response_code=200 title=t", response_code="200")
    assert golden.compare(one, one) == []


def test_compare_reports_value_and_quoting() -> None:
    old = event('title="a b" timeout=5', title="a b")
    new = event("title=a_b timeout=5", title="a_b")
    fields = [d.field for d in golden.compare(old, new)]
    assert fields == ["title", "_raw:title"]


def test_compare_reports_order_of_common_fields() -> None:
    old = event("a=1 b=2 c=3")
    new = event("b=2 a=1 c=3")
    (diff,) = golden.compare(old, new)
    assert (diff.field, diff.expected, diff.actual) == ("_raw order", "a b c", "b a c")


def test_added_field_does_not_change_order_and_can_be_allowed() -> None:
    old = event("response_code=200 timeout=5")
    new = event('response_code=200 error="boom" timeout=5', error="boom")
    diffs = golden.compare(old, new, allowed={"error"})
    assert {d.field for d in diffs} == {"error", "_raw:error"}
    assert all(d.allowed for d in diffs)
    assert golden.failing(diffs) == []
    assert golden.failing(golden.compare(old, new)) == diffs_unallowed(diffs)


def diffs_unallowed(diffs: list[golden.FieldDiff]) -> list[golden.FieldDiff]:
    return [golden.FieldDiff(d.field, d.expected, d.actual) for d in diffs]


def test_any_field_allows_everything() -> None:
    old = event("a=1 b=2", sourcetype=CHECK)
    new = event("b=3", source="web_ping://other")
    diffs = golden.compare(old, new, allowed={golden.ANY_FIELD})
    assert diffs and golden.failing(diffs) == []


def test_response_events_compare_raw_as_a_whole() -> None:
    old = event("0123456789", sourcetype=RESPONSE)
    new = event("01234", sourcetype=RESPONSE)
    assert [d.field for d in golden.compare(old, new)] == ["_raw"]


def test_sourcetype_difference_is_reported_first() -> None:
    old = event("a=1")
    new = event("a=1", sourcetype="website-ping")
    assert golden.compare(old, new)[0].field == "sourcetype"


def test_allowed_fields_merge_global_and_title() -> None:
    assert golden.allowed_fields("status-200") == {
        "error": "new in website-ping (additive)"
    }
    assert golden.ANY_FIELD in golden.allowed_fields("ntlm-offered")


# ---- Captures --------------------------------------------------------------


def row(
    time: float, sourcetype: str = CHECK, raw: str = "a=1"
) -> dict[str, golden.FieldValue]:
    return {
        "wptest_raw": raw,
        "wptest_time": str(time),
        "wptest_indextime": str(time),
        "sourcetype": sourcetype,
        "source": "web_ping://body",
    }


def test_select_capture_keeps_first_checks_and_their_requests() -> None:
    scenario = ParityScenario("body", "http://target:8080/big/10/body")
    results = [row(100, RESPONSE, "0123456789"), row(100), row(160, RESPONSE), row(160)]
    target_log: list[dict[str, object]] = [
        {"time": 99.0, "port": 8080, "path": "/big/10/body", "method": "GET",
         "user_agent": "ua", "authorization": "", "status": 200},
        {"time": 99.5, "port": 8080, "path": "/status/200", "method": "GET",
         "user_agent": "ua", "authorization": "", "status": 200},
        {"time": 159.0, "port": 8080, "path": "/big/10/body", "method": "GET",
         "user_agent": "ua", "authorization": "", "status": 200},
    ]  # fmt: skip
    item = golden.select_capture(scenario, results, target_log, [], since=50)
    assert item.complete
    assert [e.sourcetype for e in item.events] == [RESPONSE, CHECK]
    assert [r.path for r in item.requests] == ["/big/10/body"]


def test_select_capture_window_ends_at_arrival_not_at_event_time() -> None:
    scenario = ParityScenario("date-in-url", "http://target:8080/done/d?d=x")
    parsed = row(100)
    parsed["wptest_time"] = "1577934245"  # 2020-01-02, taken from the event text
    later = row(160)
    later["wptest_time"] = "1577934245"
    target_log: list[dict[str, object]] = [
        {"time": 99.0, "port": 8080, "path": "/done/d?d=x", "status": 200},
        {"time": 159.0, "port": 8080, "path": "/done/d?d=x", "status": 200},
    ]
    results = sorted([later, parsed], key=golden.arrival_order)
    item = golden.select_capture(scenario, results, target_log, [], since=50)
    assert len(item.events) == 1
    assert item.events[0].fields["_time"] == "2020-01-02T03:04:05Z"
    assert len(item.requests) == 1


def test_target_request_reads_header_fields() -> None:
    request = golden.target_request(
        {"port": 8080, "path": "/path/x/a b", "status": 400, "host": "target:8080",
         "accept": "*/*", "accept_encoding": "gzip, deflate",
         "connection": "keep-alive", "cookie": "a,b",
         "header_names": ["Host", "Accept"], "request_line": "GET /path/x/a b HTTP/1.1",
         "rejected": True}
    )  # fmt: skip
    assert request.header_names == ("Host", "Accept")
    assert (request.accept, request.cookie, request.rejected) == ("*/*", "a,b", True)
    assert golden.target_request({"port": 8080}).header_names == ()
    assert golden.target_request({"port": 8080}).rejected is False


def test_select_capture_without_events_keeps_every_request() -> None:
    scenario = ParityScenario(
        "proxy-plain", "http://target:8080/done/proxy-plain", conf="plain"
    )
    squid = [
        (120.0, ProxyRequest("GET", "http://target:8080/done/proxy-plain", "TCP_MISS/200", "-", "x")),
        (10.0, ProxyRequest("GET", "http://target:8080/done/proxy-plain", "TCP_MISS/200", "-", "x")),
    ]  # fmt: skip
    item = golden.select_capture(scenario, [], [], squid, since=50)
    assert not item.complete
    assert item.events == ()
    assert len(item.proxy_requests) == 1


def test_capture_round_trip(tmp_path: Path) -> None:
    item = golden.Capture(
        "headers",
        True,
        (event('header_X-Wptest-Space="a b \\"c\\""', **{"header_Set-Cookie": "a=1"}),),
        (
            golden.TargetRequest(
                8080,
                "GET",
                "/headers/headers",
                "ua",
                "",
                200,
                host="target:8080",
                header_names=("Host", "User-Agent"),
            ),
        ),
        (ProxyRequest("CONNECT", "target:8443", "TCP_TUNNEL/200", "-", "-"),),
    )
    golden.write_capture(tmp_path, item)
    assert golden.read_capture(tmp_path, "headers") == item
    assert golden.compare_capture(item, item) == []


def test_compare_capture_reports_counts_and_requests() -> None:
    one = golden.Capture("t", True, (event("a=1"),), (), ())
    two = golden.Capture(
        "t", False, (), (golden.TargetRequest(8080, "GET", "/x", "ua", "", 200),), ()
    )
    fields = [d.field for d in golden.compare_capture(one, two)]
    assert fields == ["complete", "event count", "requests"]
