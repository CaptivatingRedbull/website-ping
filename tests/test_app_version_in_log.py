from __future__ import annotations

from pathlib import Path

import pytest
from logger import log, setup_logging
from wp_version import read_app_version


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
