from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import FrameType
from typing import Callable, Union

import pytest
import web_ping
from logger import log_to_stderr, setup_logging
from ping_check import CheckResult
from ping_config import build_settings
from wp_context import CheckContext, make_context
from wp_deadline import Deadline
from wp_runner import STOP_WAIT
from wp_splunk import CONF_PATH

SECRET = "s3cr3t-session-key"
Handler = Union[Callable[[int, Union[FrameType, None]], object], int, None]


def config_xml(stanzas: str) -> str:
    return (
        f"<input><session_key>{SECRET}</session_key>"
        "<checkpoint_dir>/nonexistent</checkpoint_dir>"
        f"<configuration>{stanzas}</configuration></input>"
    )


GOOD = (
    '<stanza name="web_ping://good"><param name="url">http://example.invalid/</param>'
    '<param name="interval">15m</param><param name="log_level">DEBUG</param></stanza>'
)
NO_INTERVAL = (
    '<stanza name="web_ping://no-interval">'
    '<param name="url">http://example.invalid/</param></stanza>'
)
BAD_URL = (
    '<stanza name="web_ping://bad-url"><param name="url">not-a-url</param>'
    '<param name="interval">60</param></stanza>'
)


@pytest.fixture
def log_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) is not None
    yield path
    log_to_stderr()


@pytest.fixture
def restore_signals() -> Iterator[None]:
    saved: dict[int, Handler] = {
        s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)
    }
    yield
    for signum, handler in saved.items():
        _ = signal.signal(signum, handler)


def test_invalid_stanzas_are_logged_and_skipped(log_file: Path) -> None:
    settings, invalid = web_ping.load_settings(
        {
            "web_ping://good": {"url": "http://example.invalid/", "interval": "1m"},
            "web_ping://no-interval": {"url": "http://example.invalid/"},
        }
    )
    assert [s["stanza"] for s in settings] == ["web_ping://good"]
    assert invalid == 1
    (line,) = log_file.read_text(encoding="utf-8").splitlines()
    assert " ERROR stanza=web_ping://no-interval " in line
    assert line.endswith("invalid configuration, not run: interval is required")


def test_start_line_counts_and_secret_never_logged(
    log_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = web_ping.build_runner(config_xml(GOOD + NO_INTERVAL + BAD_URL))
    _ = runner.shutdown(0)
    text = log_file.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert re.search(
        r" INFO v=\S+ starting stanzas=1 invalid=2 thread_limit=200 ", text
    )
    assert "effective settings" in text  # DEBUG of the good stanza is written
    assert err.startswith("INFO starting stanzas=1 invalid=2 ")
    assert SECRET not in text and SECRET not in err


class Splunkd:
    """Answers the configuration load: [default] with the given thread_limit."""

    def __init__(self, thread_limit: str) -> None:
        self.thread_limit: str = thread_limit

    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        if path != CONF_PATH:
            return {"entry": []}
        content = {"thread_limit": self.thread_limit}
        return {"entry": [{"name": "wp_defaults", "content": content}]}


def test_thread_limit_from_website_monitoring_conf(log_file: Path) -> None:
    runner = web_ping.build_runner(config_xml(GOOD), Splunkd("50"))
    _ = runner.shutdown(0)
    text = log_file.read_text(encoding="utf-8")
    assert re.search(r" starting stanzas=1 invalid=0 thread_limit=50 ", text)
    assert " ERROR " not in text


def test_unreadable_configuration_runs_nothing(log_file: Path) -> None:
    """Outside Splunk there is no splunk.rest: the first load fails."""
    runner = web_ping.build_runner(config_xml(GOOD))
    runner.tick()
    runner.heartbeat()
    _ = runner.shutdown(0)
    text = log_file.read_text(encoding="utf-8")
    assert "cannot read configuration from splunkd" in text
    assert "thread_limit of website_monitoring.conf not known, using 200" in text
    assert re.search(r" starting stanzas=1 invalid=0 thread_limit=200 ", text)
    assert " heartbeat stanzas=1 in_flight=0 queued=0 " in text
    assert SECRET not in text


def test_no_valid_stanza_warns_and_idles(log_file: Path) -> None:
    runner = web_ping.build_runner(config_xml(NO_INTERVAL))
    runner.tick()
    assert not runner.stopping
    _ = runner.shutdown(0)
    assert "WARN v=" in log_file.read_text(encoding="utf-8")
    assert "no valid stanza" in log_file.read_text(encoding="utf-8")


def test_sigterm_stops_serve_within_the_limit(
    log_file: Path, capsys: pytest.CaptureFixture[str], restore_signals: None
) -> None:
    runner = web_ping.build_runner(config_xml(""))
    timer = threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGTERM))
    started = time.monotonic()
    timer.start()
    assert web_ping.serve(runner) == "SIGTERM"
    assert time.monotonic() - started < 0.3 + STOP_WAIT
    pid = os.getpid()
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert lines[-2].endswith(f" stopping reason=SIGTERM pid={pid}")
    assert lines[-1].endswith(f" stopped reason=SIGTERM pid={pid} abandoned=0")
    err = capsys.readouterr().err.splitlines()
    assert err[-1] == f"INFO stopped reason=SIGTERM pid={pid} abandoned=0"


def test_main_scheme_does_not_open_the_log(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("setup_logging called")

    monkeypatch.setattr(web_ping, "setup_logging", fail)
    assert web_ping.main(["web_ping.py", "--scheme"]) == 0
    assert "<use_single_instance>true</use_single_instance>" in capsys.readouterr().out


def test_run_check_logs_start_and_result(
    log_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Deadline] = []

    def fake(context: CheckContext, deadline: Deadline | None = None) -> CheckResult:
        assert deadline is not None
        seen.append(deadline)
        return CheckResult(None, elapsed=0.25, finished=1.0, error="RefusedError: no")

    monkeypatch.setattr(web_ping, "check_url", fake)
    settings, _ = build_settings(
        "web_ping://t", {"url": "http://example.invalid/", "interval": "60"}
    )
    deadline = Deadline.after(5)
    result = web_ping.run_check(make_context(settings), deadline)
    assert result.error == "RefusedError: no" and seen == [deadline]
    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert " INFO stanza=web_ping://t v=" in lines[0]
    assert lines[0].endswith(" starting check url=http://example.invalid/")
    assert lines[1].endswith(" check done code=None time=0.250 timed_out=False")
    assert " WARN stanza=web_ping://t " in lines[2]
    assert lines[2].endswith(" check failed: RefusedError: no")


def test_scheme_reaches_stdout_of_the_real_process() -> None:
    """stdout to a pipe is block-buffered, as under splunkd; os._exit must not
    drop what is still in the buffer."""
    script = Path(web_ping.__file__)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    done = subprocess.run(
        [sys.executable, str(script), "--scheme"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "<use_single_instance>true</use_single_instance>" in done.stdout
    assert done.stdout.rstrip().endswith("</scheme>")
