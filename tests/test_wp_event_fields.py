from __future__ import annotations

import dataclasses
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from ping_check import CheckResult, ProxyInfo
from ping_config import Settings, build_settings
from ping_events import escape_value, format_data
from wp_event_fields import check_event, event_fields
from wptest import golden, parity

GOLDEN_DIR = Path(__file__).parent / "golden" / "2.9.7"
FINISHED = 1700000000.25


def settings_for(title: str, **extra: str) -> Settings:
    stanza = {**parity.by_title()[title].stanza(), **extra}
    settings, _ = build_settings(f"web_ping://{title}", stanza)
    return settings


def fixture_raw(title: str) -> str:
    capture = golden.read_capture(GOLDEN_DIR, title)
    checks = [e.raw for e in capture.events if e.sourcetype == golden.CHECK_SOURCETYPE]
    return checks[0]


def answered_like(raw: str, **extra: object) -> CheckResult:
    """A result with the status and content values of a fixture's _raw."""
    values = {p.key: p.literal for p in golden.parse_raw(raw)}
    expected = values.get("has_expected_string")
    result = CheckResult(
        response_code=int(values["response_code"]),
        elapsed=0.01234,
        finished=FINISHED,
        content_md5=values.get("content_md5"),
        content_sha224=values.get("content_sha224"),
        content_size=int(values["content_size"]) if "content_size" in values else None,
        has_expected_string=None if expected is None else expected == "true",
    )
    return dataclasses.replace(result, **extra)


def rebuilt(settings: Settings, result: CheckResult) -> str:
    raw = format_data(event_fields(settings, result))
    return golden.normalise_raw(raw, golden.CHECK_SOURCETYPE)


@pytest.mark.parametrize(
    "title",
    ["status-200", "status-404", "title-escaping", "path-space", "path-unicode",
     "date-in-title", "thresholds", "match-no", "match-yes", "chain-at-3", "host-set"],
)  # fmt: skip
def test_answered_checks_match_their_fixture(title: str) -> None:
    raw = fixture_raw(title)
    assert rebuilt(settings_for(title), answered_like(raw)) == raw


def test_headers_go_between_timeout_and_proxy() -> None:
    raw = fixture_raw("headers")
    headers = (
        ("Server", "BaseHTTP/0.6 Python/3.12.3"),
        ("Date", "Sat, 14 Nov 2026 08:00:00 GMT"),
        ("X-Wptest", "one"),
        ("X-Wptest-Space", 'a b "c"'),
        ("Set-Cookie", "a=1, b=2"),
        ("Content-Length", "2"),
    )
    result = answered_like(raw, headers=headers)
    assert rebuilt(settings_for("headers"), result) == raw


def test_proxy_user_goes_between_type_and_port() -> None:
    raw = fixture_raw("proxy-auth")
    proxy = ProxyInfo(server="squid", type="http", port="3129", user="wpproxy")
    assert rebuilt(settings_for("proxy-auth"), answered_like(raw, proxy=proxy)) == raw


@pytest.mark.parametrize(
    ("title", "result"),
    [
        ("refused", CheckResult(None, 0.002, FINISHED, error="ConnectionRefusedError: [Errno 111] Connection refused")),
        ("dns-failure", CheckResult(None, 0.002, FINISHED, error="gaierror: [Errno -2] Name or service not known")),
        ("timeout", CheckResult(None, 5.0, FINISHED, timed_out=True)),
        ("slow-body", CheckResult(None, 5.0, FINISHED, timed_out=True)),
        ("over-3", CheckResult(None, 0.01, FINISHED, exceeded_redirects=True, error="redirect limit of 3 reached")),
        ("redirects-off", CheckResult(None, 0.01, FINISHED, exceeded_redirects=True, error="redirect limit of 0 reached")),
        ("blank-31", CheckResult(None, 0.01, FINISHED, exceeded_redirects=True, error="redirect limit of 30 reached")),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)  # fmt: skip
def test_failures_match_their_fixture_plus_error(
    title: str, result: CheckResult
) -> None:
    expected = fixture_raw(title)
    if result.error:
        expected += f" error={escape_value(result.error)}"
    assert rebuilt(settings_for(title), result) == expected


def test_no_response_empties_code_and_times() -> None:
    fields = dict(
        event_fields(
            settings_for("refused"), CheckResult(None, 0.5, FINISHED, error="x")
        )
    )
    assert fields["response_code"] == fields["total_time"] == ""
    assert fields["request_time"] == ""
    assert fields["timed_out"] is False


def test_times_are_milliseconds_rounded_to_two_places() -> None:
    fields = dict(
        event_fields(settings_for("status-200"), CheckResult(200, 0.1234567, FINISHED))
    )
    assert fields["total_time"] == fields["request_time"] == 123.46


@pytest.mark.parametrize(
    ("value", "shown"), [("", None), ("-1", None), ("0", 0), ("7", 7)]
)
def test_max_redirects_only_when_configured(value: str, shown: int | None) -> None:
    settings = settings_for("status-200", max_redirects=value)
    fields = dict(event_fields(settings, CheckResult(200, 0.1, FINISHED)))
    assert fields.get("max_redirects") == shown


def test_thresholds_only_when_set() -> None:
    settings = settings_for("status-200", warning_threshold="100")
    keys = [key for key, _ in event_fields(settings, CheckResult(200, 0.1, FINISHED))]
    assert "warning_threshold" in keys and "error_threshold" not in keys


def test_error_is_the_last_field() -> None:
    settings = settings_for("over-3", warning_threshold="1", error_threshold="2")
    result = CheckResult(None, 0.1, FINISHED, exceeded_redirects=True, error="boom")
    assert [key for key, _ in event_fields(settings, result)][-6:] == [
        "proxy_port",
        "exceeded_redirects",
        "max_redirects",
        "warning_threshold",
        "error_threshold",
        "error",
    ]


def test_check_event_envelope() -> None:
    settings = settings_for("status-200", index="web", sourcetype="custom")
    event = ET.fromstring(check_event(settings, CheckResult(200, 0.1, FINISHED)))
    node = event.find("event")
    assert node is not None
    assert node.get("stanza") == "web_ping://status-200"
    assert node.findtext("time") == "1700000000.250"
    assert node.findtext("index") == "web"
    assert node.findtext("sourcetype") == "custom"
    assert node.findtext("source") == "web_ping://status-200"
    assert node.find("host") is None
    assert (node.findtext("data") or "").startswith("response_code=200 ")


@pytest.mark.parametrize(
    ("host", "written"), [("$decideOnStartup", None), ("web01", "web01")]
)
def test_check_event_host(host: str, written: str | None) -> None:
    settings = settings_for("status-200", host=host)
    event = ET.fromstring(check_event(settings, CheckResult(200, 0.1, FINISHED)))
    assert event.findtext("event/host") == written
