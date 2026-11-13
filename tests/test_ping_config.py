from __future__ import annotations

import configparser
from collections.abc import Mapping
from pathlib import Path

import pytest
from ping_config import (
    DEFAULT_USER_AGENT,
    UNLIMITED_REDIRECTS,
    ConfigError,
    Settings,
    build_settings,
)

STANZA = "web_ping://example"
URL = "https://example.com/"
APP_CONF = Path(__file__).absolute().parent.parent / "default" / "app.conf"
SECRET = "s3cr3t-Pa55"


def build(**params: str) -> Settings:
    settings, _ = build_settings(STANZA, {"url": URL, "interval": "60", **params})
    return settings


def warnings_for(**params: str) -> list[str]:
    _, warnings = build_settings(STANZA, {"url": URL, "interval": "60", **params})
    return warnings


def test_defaults() -> None:
    settings, warnings = build_settings(STANZA, {"url": URL, "interval": "60"})
    assert warnings == []
    assert settings == {
        "stanza": STANZA,
        "name": "example",
        "url": URL,
        "title": URL,
        "interval": 60,
        "timeout": 30,
        "max_redirects": None,
        "user_agent": DEFAULT_USER_AGENT,
        "should_contain_string": None,
        "return_body": False,
        "return_headers": False,
        "warning_threshold": None,
        "error_threshold": None,
        "configuration": "default",
        "username": None,
        "client_certificate": None,
        "client_certificate_key": None,
        "ssl_verify": None,
        "ca_certs": None,
        "log_level": "INFO",
        "index": None,
        "host": None,
        "sourcetype": "web_ping",
    }


def test_unlimited_redirects_constant() -> None:
    assert UNLIMITED_REDIRECTS == 30


# ---- url -------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com:8443/a b?q=1",
        "  http://target:8080/x  ",
    ],
)
def test_url_accepted(url: str) -> None:
    assert build(url=url)["url"] == url.strip()


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com",
        "not-a-url",
        "http://",
        "http:///path",
        "http://[::1",
    ],
)
def test_url_rejected(url: str) -> None:
    with pytest.raises(ConfigError, match="url"):
        _ = build(url=url)


@pytest.mark.parametrize(
    "url",
    [
        f"http://user:{SECRET}@example.com/",
        f"https://{SECRET}@example.com/",
        f"http://:{SECRET}@example.com/",
        f"ftp://user:{SECRET}@example.com/",
    ],
)
def test_url_with_userinfo_rejected_without_value(url: str) -> None:
    with pytest.raises(ConfigError) as info:
        _ = build(url=url)
    message = str(info.value)
    assert "user name or password" in message
    assert STANZA in message
    assert SECRET not in message
    assert "@" not in message


def test_url_without_scheme_and_at_sign_is_not_echoed() -> None:
    with pytest.raises(ConfigError) as info:
        _ = build(url=f"user:{SECRET}@example.com")
    assert SECRET not in str(info.value)


def test_at_sign_in_path_or_query_is_not_userinfo() -> None:
    url = "https://example.com/path@x?mail=a@b.c"
    assert build(url=url)["url"] == url


# ---- title -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"), [("", URL), ("  ", URL), (" Shop ", "Shop")]
)
def test_title(raw: str, expected: str) -> None:
    assert build(title=raw)["title"] == expected


# ---- interval --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [
        ("30s", 30),
        ("90", 90),
        ("15m", 900),
        ("15 m", 900),
        ("15min", 900),
        ("15minute", 900),
        ("2h", 7200),
        ("2hour", 7200),
        ("1d", 86400),
        ("1day", 86400),
        ("1w", 604800),
        ("1week", 604800),
        ("0", 0),
    ],
)
def test_interval_accepted(raw: str, seconds: int) -> None:
    assert build(interval=raw)["interval"] == seconds
    assert warnings_for(interval=raw) == []


@pytest.mark.parametrize(
    "raw", ["", "  ", "15minutes", "15M", "15S", "abc", "-5", "m15", "*/5 * * * *"]
)
def test_interval_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match="interval"):
        _ = build(interval=raw)


def test_interval_missing_rejected() -> None:
    with pytest.raises(ConfigError, match="interval is required"):
        _ = build_settings(STANZA, {"url": URL})


def test_interval_trailing_text_ignored_with_warning() -> None:
    settings, warnings = build_settings(STANZA, {"url": URL, "interval": "15m garbage"})
    assert settings["interval"] == 900
    assert len(warnings) == 1
    assert "garbage" in warnings[0]


@pytest.mark.parametrize(
    ("params", "seconds"),
    [({}, 0), ({"interval": ""}, 0), ({"interval": "*/5 * * * *"}, 0),
     ({"interval": "15M"}, 0), ({"interval": "15m"}, 900)],
)  # fmt: skip
def test_interval_not_required(params: Mapping[str, str], seconds: int) -> None:
    settings, warnings = build_settings(
        STANZA, {"url": URL, **params}, require_interval=False
    )
    assert settings["interval"] == seconds
    assert warnings == []


# ---- timeout ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "seconds"), [("", 30), ("5", 5), (" 7 ", 7), ("600", 600)]
)
def test_timeout_accepted(raw: str, seconds: int) -> None:
    assert build(timeout=raw)["timeout"] == seconds
    assert warnings_for(timeout=raw) == []


@pytest.mark.parametrize("raw", ["0", "-5"])
def test_timeout_not_positive_warns_and_uses_default(raw: str) -> None:
    settings, warnings = build_settings(
        STANZA, {"url": URL, "interval": "60", "timeout": raw}
    )
    assert settings["timeout"] == 30
    assert len(warnings) == 1 and "timeout" in warnings[0]


@pytest.mark.parametrize("raw", ["abc", "1.5", "30s"])
def test_timeout_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match="timeout"):
        _ = build(timeout=raw)


# ---- max_redirects ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"), [("", None), ("-1", None), ("-7", None), ("0", 0), ("7", 7)]
)
def test_max_redirects(raw: str, expected: int | None) -> None:
    assert build(max_redirects=raw)["max_redirects"] == expected


def test_max_redirects_rejected() -> None:
    with pytest.raises(ConfigError, match="max_redirects"):
        _ = build(max_redirects="many")


# ---- should_contain_string -------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"), [("", None), ("   ", None), ("Welcome", "Welcome")]
)
def test_should_contain_string(raw: str, expected: str | None) -> None:
    assert build(should_contain_string=raw)["should_contain_string"] == expected


# ---- booleans --------------------------------------------------------------


@pytest.mark.parametrize("key", ["return_body", "return_headers"])
@pytest.mark.parametrize(
    ("raw", "expected"),
    [("True", True), ("true", True), (" 1 ", True), ("FALSE", False), ("0", False),
     ("", False)],
)  # fmt: skip
def test_booleans(key: str, raw: str, expected: bool) -> None:
    assert build(**{key: raw})[key] is expected


@pytest.mark.parametrize("key", ["return_body", "return_headers", "ssl_verify"])
@pytest.mark.parametrize("raw", ["yes", "no", "on", "2"])
def test_booleans_rejected(key: str, raw: str) -> None:
    with pytest.raises(ConfigError, match=key):
        _ = build(**{key: raw})


@pytest.mark.parametrize(
    ("raw", "expected"), [("", None), ("true", True), ("0", False)]
)
def test_ssl_verify(raw: str, expected: bool | None) -> None:
    assert build(ssl_verify=raw)["ssl_verify"] is expected


# ---- thresholds ------------------------------------------------------------


@pytest.mark.parametrize("key", ["warning_threshold", "error_threshold"])
@pytest.mark.parametrize(
    ("raw", "expected"), [("", None), ("-1", None), ("0", 0), ("1500", 1500)]
)
def test_thresholds(key: str, raw: str, expected: int | None) -> None:
    assert build(**{key: raw})[key] == expected


@pytest.mark.parametrize("key", ["warning_threshold", "error_threshold"])
def test_thresholds_rejected(key: str) -> None:
    with pytest.raises(ConfigError, match=key):
        _ = build(**{key: "1s"})


# ---- strings with defaults -------------------------------------------------


def test_user_agent_default_contains_app_version() -> None:
    parser = configparser.ConfigParser(interpolation=None)
    _ = parser.read(APP_CONF, encoding="utf-8")
    version = parser.get("launcher", "version").strip()
    assert DEFAULT_USER_AGENT == f"Splunk Website Ping/{version}"
    assert build(user_agent="")["user_agent"] == DEFAULT_USER_AGENT


def test_user_agent_set() -> None:
    assert build(user_agent="Mozilla/5.0 (X11)")["user_agent"] == "Mozilla/5.0 (X11)"


@pytest.mark.parametrize(
    ("raw", "expected"), [("", "default"), (" ", "default"), ("proxy_b", "proxy_b")]
)
def test_configuration(raw: str, expected: str) -> None:
    assert build(configuration=raw)["configuration"] == expected


@pytest.mark.parametrize(
    "key",
    ["username", "client_certificate", "client_certificate_key", "ca_certs", "index",
     "host"],
)  # fmt: skip
def test_optional_strings(key: str) -> None:
    assert build(**{key: ""})[key] is None
    assert build(**{key: " value "})[key] == "value"


def test_host_decide_on_startup_kept() -> None:
    assert build(host="$decideOnStartup")["host"] == "$decideOnStartup"


@pytest.mark.parametrize(("raw", "expected"), [("", "web_ping"), ("custom", "custom")])
def test_sourcetype(raw: str, expected: str) -> None:
    assert build(sourcetype=raw)["sourcetype"] == expected


@pytest.mark.parametrize(
    ("raw", "expected"), [("", "INFO"), ("debug", "DEBUG"), ("WARN", "WARN")]
)
def test_log_level(raw: str, expected: str) -> None:
    assert build(log_level=raw)["log_level"] == expected
    assert warnings_for(log_level=raw) == []


def test_log_level_unknown_warns() -> None:
    settings, warnings = build_settings(
        STANZA, {"url": URL, "interval": "60", "log_level": "verbose"}
    )
    assert settings["log_level"] == "INFO"
    assert len(warnings) == 1 and "log_level" in warnings[0]


# ---- password --------------------------------------------------------------


def test_plain_password_rejected_without_value() -> None:
    with pytest.raises(ConfigError) as info:
        _ = build(username="admin", password=SECRET)
    message = str(info.value)
    assert SECRET not in message
    assert "storage/passwords" in message
    assert f"realm {STANZA}" in message


@pytest.mark.parametrize("raw", ["", "        "])
def test_blank_password_accepted(raw: str) -> None:
    """Website Monitoring's UI replaced a stored password with spaces in inputs.conf."""
    settings = build(username="admin", password=raw)
    assert settings["username"] == "admin"
    assert "password" not in settings


def test_password_rejected_before_other_errors() -> None:
    with pytest.raises(ConfigError) as info:
        _ = build(password=SECRET, timeout="abc", interval="bad")
    assert "password" in str(info.value)
    assert SECRET not in str(info.value)


# ---- other keys ------------------------------------------------------------


def test_unknown_keys_ignored() -> None:
    settings = build(**{"python.version": "python3", "disabled": "0", "foo": "bar"})
    assert "foo" not in settings
    assert "disabled" not in settings


def test_error_names_setting_and_value() -> None:
    with pytest.raises(ConfigError) as info:
        _ = build(timeout="abc")
    assert "timeout" in str(info.value)
    assert "'abc'" in str(info.value)
