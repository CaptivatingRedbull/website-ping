from __future__ import annotations

import logging
import re
import threading
from collections.abc import Iterator
from pathlib import Path

import logger
import pytest
from logger import (
    CONSOLE,
    log_file_path,
    log_to_stderr,
    process_log,
    setup_logging,
    stanza_logger,
)
from wp_version import APP_VERSION

STAMP = r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} [+-]\d{4}"


@pytest.fixture(autouse=True)
def restore_stderr() -> Iterator[None]:
    yield
    log_to_stderr()


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) == str(path)
    return path


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_file_line_format(log_file: Path) -> None:
    stanza_logger("web_ping://t").info("hello %s", "there")
    process_log.warning("process line")
    first, second = lines(log_file)
    assert re.fullmatch(
        rf"{STAMP} INFO stanza=web_ping://t v={re.escape(APP_VERSION)} hello there",
        first,
    ), first
    assert re.fullmatch(
        rf"{STAMP} WARN v={re.escape(APP_VERSION)} process line", second
    ), second


def test_stanza_with_space_is_quoted(log_file: Path) -> None:
    stanza_logger('web_ping://my "site"').info("x")
    assert ' stanza="web_ping://my \\"site\\"" ' in lines(log_file)[0]


def test_real_debug_level_and_per_stanza_filter(log_file: Path) -> None:
    stanza_logger("web_ping://d", "DEBUG").debug("shown")
    stanza_logger("web_ping://i", "INFO").debug("dropped")
    stanza_logger("web_ping://e", "error").warning("dropped too")
    (line,) = lines(log_file)
    assert " DEBUG stanza=web_ping://d " in line
    assert "[debug]" not in line


def test_traceback_stays_on_one_line(log_file: Path) -> None:
    try:
        raise ValueError("first\nsecond")
    except ValueError:
        stanza_logger("web_ping://t").exception("failed")
    (line,) = lines(log_file)
    assert "failed | Traceback" in line
    assert "ValueError: first | second" in line


def test_only_console_lines_reach_stderr(
    log_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    slog = stanza_logger("web_ping://t", "DEBUG")
    slog.info("start", extra=CONSOLE)
    slog.error("file only")
    assert capsys.readouterr().err.splitlines() == ["INFO stanza=web_ping://t start"]
    assert len(lines(log_file)) == 2


def test_records_from_two_threads_never_interleave(log_file: Path) -> None:
    count = 2000
    text = {"a": "a" * 300, "b": "b" * 300}

    def write(name: str) -> None:
        slog = stanza_logger(f"web_ping://{name}")
        for i in range(count):
            slog.info("%d %s", i, text[name])

    threads = [threading.Thread(target=write, args=(name,)) for name in text]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    pattern = re.compile(
        rf"{STAMP} INFO stanza=web_ping://(?P<n>[ab]) v=\S+ \d+ (?P<t>[ab]{{300}})"
    )
    seen = {"a": 0, "b": 0}
    for line in lines(log_file):
        match = pattern.fullmatch(line)
        assert match is not None, line
        assert match["t"] == text[match["n"]]
        seen[match["n"]] += 1
    assert seen == {"a": count, "b": count}


def test_rotation_keeps_backups(tmp_path: Path) -> None:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path), max_bytes=1000, backup_count=2) is not None
    for i in range(100):
        process_log.info("line %d %s", i, "x" * 50)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["website_ping.log", "website_ping.log.1", "website_ping.log.2"]
    assert all(p.stat().st_size <= 1000 for p in tmp_path.iterdir())


def test_unusable_path_falls_back_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "not-a-directory"
    _ = blocker.write_text("")
    path = blocker / "website_ping.log"
    assert setup_logging(str(path)) is None
    stanza_logger("web_ping://t", "DEBUG").debug("still logged")
    err = capsys.readouterr().err.splitlines()
    assert len(err) == 2
    assert err[0].startswith(f"ERROR v={APP_VERSION} cannot open log file {path} (")
    assert err[0].endswith("), logging to stderr")
    assert err[1] == f"INFO stanza=web_ping://t v={APP_VERSION} [debug] still logged"


def test_no_splunk_home_falls_back_to_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SPLUNK_HOME", raising=False)
    assert setup_logging() is None
    assert capsys.readouterr().err == (
        f"ERROR v={APP_VERSION} SPLUNK_HOME is not set, logging to stderr\n"
    )


def test_log_file_path() -> None:
    assert log_file_path({"SPLUNK_HOME": "/opt/splunk"}) == (
        "/opt/splunk/var/log/splunk/website_ping.log"
    )
    assert log_file_path({}) is None


def test_setup_again_closes_the_previous_file(tmp_path: Path) -> None:
    _ = setup_logging(str(tmp_path / "one.log"))
    first = logger.log.handlers[0]
    assert isinstance(first, logging.FileHandler)
    _ = setup_logging(str(tmp_path / "two.log"))
    assert first.stream is None  # closed
