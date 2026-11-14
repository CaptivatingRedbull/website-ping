from __future__ import annotations

import io
import platform
import re
import ssl
import sys
from pathlib import Path

import pytest
import web_ping
from logger import log, setup_logging
from ping_check import CheckResult
from ping_config import Settings
from wp_version import read_app_version, runtime_versions

CONFIG_XML = (
    '<input><configuration><stanza name="web_ping://t">'
    '<param name="url">http://example.invalid/</param>'
    "</stanza></configuration></input>"
)


def test_reads_version(tmp_path: Path) -> None:
    conf = tmp_path / "app.conf"
    _ = conf.write_text("[launcher]\nversion = 1.2.3\n")
    assert read_app_version(conf) == "1.2.3"


def test_missing_file_gives_unknown(tmp_path: Path) -> None:
    assert read_app_version(tmp_path / "nope.conf") == "unknown"


def test_error_has_version_but_info_does_not(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _ = setup_logging("INFO", "x")
    log.info("hello")
    log.error("boom")
    lines = capsys.readouterr().err.splitlines()
    assert " v=" not in lines[0]
    assert " v=" in lines[1]


def test_runtime_versions_name_interpreter_and_openssl() -> None:
    match = re.fullmatch(
        r'python=(\d+\.\d+\.\d+) openssl="([^"]+)"', runtime_versions()
    )
    assert match is not None
    assert match.group(1) == platform.python_version()
    assert match.group(2) == ssl.OPENSSL_VERSION


class _Stop(Exception):
    pass


def _stop(_settings: Settings) -> CheckResult:
    raise _Stop


def test_start_line_carries_runtime_versions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(CONFIG_XML))
    monkeypatch.setattr(web_ping, "check_url", _stop)
    with pytest.raises(_Stop):
        web_ping.ping()
    starts = [
        line
        for line in capsys.readouterr().err.splitlines()
        if "starting check" in line
    ]
    assert starts == [
        f"INFO stanza=web_ping://t starting check url=http://example.invalid/ {runtime_versions()}"
    ]
