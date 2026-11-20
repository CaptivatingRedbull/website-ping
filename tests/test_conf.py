"""Reading Splunk .conf files (wptest/conf.py)."""

from __future__ import annotations

import pytest
from wptest.conf import parse_conf


def test_continuations_comments_and_global_settings() -> None:
    text = (
        "top = 1\n"
        "# comment\n"
        "\n"
        "[one]\n"
        "search = a \\\n"
        "| b \\\n"
        "| c\n"
        "key=value = with equals\n"
        "[]\n"
        "access = read : [ * ]\n"
    )
    assert parse_conf(text) == {
        "default": {"top": "1"},
        "one": {"search": "a \n| b \n| c", "key": "value = with equals"},
        "": {"access": "read : [ * ]"},
    }


def test_a_line_without_equals_sign_is_an_error() -> None:
    with pytest.raises(ValueError, match="not a setting"):
        _ = parse_conf("[one]\njust text\n")
