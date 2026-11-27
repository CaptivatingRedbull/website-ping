from __future__ import annotations

import os
import platform
import re
import ssl
from collections.abc import Mapping
from pathlib import Path

import pytest
import web_ping
from logger import log_to_stderr, setup_logging, stanza_logger
from wp_version import read_app_version, runtime_versions

CONFIG_XML = (
    "<input><checkpoint_dir>/nonexistent</checkpoint_dir>"
    '<configuration><stanza name="web_ping://t">'
    '<param name="url">http://example.invalid/</param>'
    '<param name="interval">1h</param>'
    "</stanza></configuration></input>"
)


class EmptyConfig:
    """splunkd with website_monitoring.conf as shipped and no stored password."""

    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        content: dict[str, str] = {}
        return {"entry": [{"name": "wp_defaults", "content": content}]}


def test_reads_version(tmp_path: Path) -> None:
    conf = tmp_path / "app.conf"
    _ = conf.write_text("[launcher]\nversion = 1.2.3\n")
    assert read_app_version(conf) == "1.2.3"


def test_missing_file_gives_unknown(tmp_path: Path) -> None:
    assert read_app_version(tmp_path / "nope.conf") == "unknown"


def test_stderr_error_has_version_but_info_does_not(
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_to_stderr()
    slog = stanza_logger("x")
    slog.info("hello")
    slog.error("boom")
    lines = capsys.readouterr().err.splitlines()
    assert " v=" not in lines[0]
    assert " v=" in lines[1]


def test_runtime_versions_name_interpreter_openssl_and_flavor() -> None:
    match = re.fullmatch(
        r'python=(\d+\.\d+\.\d+) openssl="([^"]+)" flavor=(\S+)', runtime_versions()
    )
    assert match is not None
    assert match.group(1) == platform.python_version()
    assert match.group(2) == ssl.OPENSSL_VERSION
    assert match.group(3) == "drop-in"


def test_start_line_carries_runtime_versions(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    log_dir = tmp_path / "var" / "log" / "splunk"
    log_dir.mkdir(parents=True)
    monkeypatch.setenv("SPLUNK_HOME", str(tmp_path))
    try:
        assert setup_logging() is not None
        runner = web_ping.build_runner(CONFIG_XML, EmptyConfig())
        _ = runner.shutdown(0)
    finally:
        log_to_stderr()
    start = (
        rf"starting stanzas=1 invalid=0 thread_limit=200 pid={os.getpid()}"
        f" {re.escape(runtime_versions())}"
    )
    assert re.fullmatch(f"INFO {start}", capsys.readouterr().err.strip())
    (line,) = (log_dir / "website_ping.log").read_text(encoding="utf-8").splitlines()
    assert re.search(f" INFO v=\\S+ {start}$", line), line
