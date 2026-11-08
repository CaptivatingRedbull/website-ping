from __future__ import annotations

from collections.abc import Mapping
from typing import TypedDict
from urllib.parse import urlparse

DEFAULT_USER_AGENT = "website-ping/0.1 (Splunk modular input)"


class ConfigError(ValueError):
    """The stanza is misconfigured. This is a bug in inputs.conf, not an outage."""


class Settings(TypedDict):
    url: str
    title: str
    timeout: int
    max_redirects: int
    user_agent: str


def _int(
    params: Mapping[str, str], key: str, default: int, minimum: int, maximum: int
) -> int:
    raw = params.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{key} must be between {minimum} and {maximum}, got {value}")
    return value


def build_settings(params: Mapping[str, str]) -> Settings:
    """Turn the raw stanza params into validated settings with defaults applied."""
    url = params.get("url", "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigError(f"url must be an http(s) URL, got {url!r}")
    return {
        "url": url,
        "title": params.get("title", "").strip() or url,
        "timeout": _int(params, "timeout", 30, 1, 300),
        "max_redirects": _int(params, "max_redirects", 10, 0, 50),
        "user_agent": params.get("user_agent", "").strip() or DEFAULT_USER_AGENT,
    }
