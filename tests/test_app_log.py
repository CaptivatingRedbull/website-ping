from __future__ import annotations

from datetime import datetime

from wptest.stack import parse_app_log


def test_parse_app_log_orders_lines_and_skips_others() -> None:
    text = (
        "2026-11-16 12:00:01,500 +0100 INFO v=1 second\n"
        "not a log line\n"
        "2026-11-16 12:00:00,250 +0100 ERROR stanza=web_ping://a v=1 first\n"
    )
    parsed = parse_app_log(text)
    assert [line.rsplit(" ", 1)[1] for _, line in parsed] == ["first", "second"]
    expected = datetime.fromisoformat("2026-11-16T12:00:00.250+01:00").timestamp()
    assert parsed[0][0] == expected
