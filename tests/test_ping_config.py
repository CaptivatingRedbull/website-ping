from __future__ import annotations

import pytest
from ping_config import ConfigError, build_settings


def test_defaults() -> None:
    s = build_settings({"url": "https://example.com"})
    assert s["timeout"] == 30
    assert s["title"] == "https://example.com"


def test_rejects_non_http_url() -> None:
    with pytest.raises(ConfigError):
        _ = build_settings({"url": "ftp://example.com"})


def test_rejects_bad_timeout() -> None:
    with pytest.raises(ConfigError):
        _ = build_settings({"url": "https://example.com", "timeout": "abc"})
