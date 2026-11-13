"""Turn the parameters of one [web_ping://...] stanza into typed settings.

Every value Website Monitoring 2.9.7 accepted is accepted with the same meaning;
values it rejected raise ConfigError. Plain-text credentials are refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TypedDict
from urllib.parse import urlsplit

from logger import LOG_LEVELS
from wp_version import APP_VERSION

DEFAULT_USER_AGENT = f"Splunk Website Ping/{APP_VERSION}"
DEFAULT_TIMEOUT = 30
DEFAULT_CONFIGURATION = "default"
DEFAULT_SOURCETYPE = "web_ping"
DEFAULT_LOG_LEVEL = "INFO"
UNLIMITED_REDIRECTS = 30
"""Redirects followed when max_redirects is blank or negative (the requests default
that Website Monitoring relied on)."""

# Same pattern as Website Monitoring's DurationField: anchored at the start only, so
# text after the unit is ignored. The unit lookup below is case-sensitive.
_DURATION = re.compile(r"(?P<duration>[0-9]+)\s*(?P<units>[a-z]*)", re.IGNORECASE)
_MINUTE = 60
_HOUR = 60 * _MINUTE
_DAY = 24 * _HOUR
_WEEK = 7 * _DAY
DURATION_UNITS: Mapping[str, int] = {
    "w": _WEEK,
    "week": _WEEK,
    "d": _DAY,
    "day": _DAY,
    "h": _HOUR,
    "hour": _HOUR,
    "m": _MINUTE,
    "min": _MINUTE,
    "minute": _MINUTE,
    "s": 1,
}

_TRUE = ("true", "1")
_FALSE = ("false", "0")


class ConfigError(ValueError):
    """The stanza is misconfigured. This is a bug in inputs.conf, not an outage."""


class Settings(TypedDict):
    stanza: str
    """Full stanza name, web_ping://<name>."""
    name: str
    url: str
    title: str
    interval: int
    """Seconds."""
    timeout: int
    """Seconds."""
    max_redirects: int | None
    """None = unlimited (UNLIMITED_REDIRECTS), 0 = do not follow."""
    user_agent: str
    should_contain_string: str | None
    return_body: bool
    return_headers: bool
    warning_threshold: int | None
    """Milliseconds."""
    error_threshold: int | None
    """Milliseconds."""
    configuration: str
    """Stanza of website_monitoring.conf."""
    username: str | None
    client_certificate: str | None
    client_certificate_key: str | None
    ssl_verify: bool | None
    """None = use the default from website_monitoring.conf."""
    ca_certs: str | None
    log_level: str
    index: str | None
    host: str | None
    sourcetype: str


def parse_duration(key: str, raw: str) -> tuple[int, str]:
    """Return (seconds, ignored trailing text) for values like 30, 30s, 15m, 2h, 1d, 1w."""
    value = raw.strip()
    match = _DURATION.match(value)
    if match is None:
        raise ConfigError(
            f"{key} must be a duration such as 30s, 15m, 2h, 1d or 1w, got {raw!r}"
        )
    units = match["units"]
    if units and units not in DURATION_UNITS:
        raise ConfigError(
            f"{key} has an unknown unit {units!r} in {raw!r};"
            " use one of w, week, d, day, h, hour, m, min, minute, s (lower case)"
        )
    seconds = int(match["duration"]) * (DURATION_UNITS[units] if units else 1)
    return seconds, value[match.end() :].strip()


def parse_bool(key: str, raw: str) -> bool | None:
    """true/1 and false/0 in any case; blank is None."""
    value = raw.strip().lower()
    if not value:
        return None
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{key} must be true, false, 1 or 0, got {raw!r}")


def parse_int(key: str, raw: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from None


def parse_optional_int(key: str, raw: str) -> int | None:
    """Blank or negative is None (unset)."""
    if not raw.strip():
        return None
    value = parse_int(key, raw)
    return value if value >= 0 else None


def _text(params: Mapping[str, str], key: str) -> str:
    return params.get(key, "").strip()


def _optional_text(params: Mapping[str, str], key: str) -> str | None:
    return _text(params, key) or None


def _shown(url: str) -> str:
    """The URL for an error message, unless it may contain a password."""
    return "(not shown, it contains '@')" if "@" in url else repr(url)


def _parse_url(stanza: str, raw: str) -> str:
    url = raw.strip()
    if not url:
        raise ConfigError("url is required")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ConfigError(f"url is not a valid URL: {exc}") from None
    if "@" in parts.netloc:
        raise ConfigError(
            "url with a user name or password is not supported;"
            " set username and store the password in storage/passwords"
            f" with realm {stanza}"
        )
    if parts.scheme not in ("http", "https"):
        raise ConfigError(f"url must use http or https, got {_shown(url)}")
    if not parts.hostname:
        raise ConfigError(f"url has no host name, got {_shown(url)}")
    return url


def _parse_interval(raw: str, required: bool, warnings: list[str]) -> int:
    if not raw.strip():
        if required:
            raise ConfigError("interval is required")
        return 0
    try:
        seconds, ignored = parse_duration("interval", raw)
    except ConfigError:
        if required:
            raise
        return 0
    if ignored:
        warnings.append(
            f"interval {raw!r}: text after the unit is ignored ({ignored!r})"
        )
    return seconds


def _parse_timeout(raw: str, warnings: list[str]) -> int:
    if not raw.strip():
        return DEFAULT_TIMEOUT
    timeout = parse_int("timeout", raw)
    if timeout <= 0:
        warnings.append(f"timeout {timeout} is not positive, using {DEFAULT_TIMEOUT}")
        return DEFAULT_TIMEOUT
    return timeout


def _parse_log_level(raw: str, warnings: list[str]) -> str:
    level = raw.strip().upper()
    if not level:
        return DEFAULT_LOG_LEVEL
    if level not in LOG_LEVELS:
        warnings.append(
            f"log_level {raw!r} is not one of {', '.join(LOG_LEVELS)},"
            f" using {DEFAULT_LOG_LEVEL}"
        )
        return DEFAULT_LOG_LEVEL
    return level


def build_settings(
    stanza: str, params: Mapping[str, str], *, require_interval: bool = True
) -> tuple[Settings, list[str]]:
    """Validate the raw stanza params and apply defaults.

    Returns the settings and warnings for the caller to log. Raises ConfigError for a
    value that makes the stanza unusable; the message never contains a password.
    Unknown keys are ignored. With require_interval=False a missing or unparsable
    interval becomes 0 (splunkd schedules the input itself).
    """
    warnings: list[str] = []
    if _text(params, "password"):
        raise ConfigError(
            "password in inputs.conf is not supported;"
            f" store it in storage/passwords with realm {stanza}"
        )
    url = _parse_url(stanza, params.get("url", ""))
    should_contain = params.get("should_contain_string", "")
    settings: Settings = {
        "stanza": stanza,
        "name": stanza.split("://", 1)[-1],
        "url": url,
        "title": _text(params, "title") or url,
        "interval": _parse_interval(
            params.get("interval", ""), require_interval, warnings
        ),
        "timeout": _parse_timeout(params.get("timeout", ""), warnings),
        "max_redirects": parse_optional_int(
            "max_redirects", params.get("max_redirects", "")
        ),
        "user_agent": _text(params, "user_agent") or DEFAULT_USER_AGENT,
        "should_contain_string": should_contain if should_contain.strip() else None,
        "return_body": parse_bool("return_body", params.get("return_body", ""))
        or False,
        "return_headers": parse_bool("return_headers", params.get("return_headers", ""))
        or False,
        "warning_threshold": parse_optional_int(
            "warning_threshold", params.get("warning_threshold", "")
        ),
        "error_threshold": parse_optional_int(
            "error_threshold", params.get("error_threshold", "")
        ),
        "configuration": _text(params, "configuration") or DEFAULT_CONFIGURATION,
        "username": _optional_text(params, "username"),
        "client_certificate": _optional_text(params, "client_certificate"),
        "client_certificate_key": _optional_text(params, "client_certificate_key"),
        "ssl_verify": parse_bool("ssl_verify", params.get("ssl_verify", "")),
        "ca_certs": _optional_text(params, "ca_certs"),
        "log_level": _parse_log_level(params.get("log_level", ""), warnings),
        "index": _optional_text(params, "index"),
        "host": _optional_text(params, "host"),
        "sourcetype": _text(params, "sourcetype") or DEFAULT_SOURCETYPE,
    }
    return settings, warnings
