from __future__ import annotations

from pathlib import Path

from logger import log_to_stderr, setup_logging
from wp_deadline import Deadline


class Clock:
    def __init__(self) -> None:
        self.now: float = 10.0

    def __call__(self) -> float:
        return self.now


def test_remaining_and_passed() -> None:
    clock = Clock()
    deadline = Deadline.after(5, clock)
    assert deadline.at == 15.0
    assert deadline.remaining() == 5.0 and not deadline.passed()
    clock.now = 15.0
    assert deadline.remaining() == 0.0 and deadline.passed()
    assert not deadline.expired


def test_expire_runs_callbacks_once() -> None:
    deadline = Deadline(100.0, Clock())
    calls: list[str] = []
    deadline.on_expire(lambda: calls.append("a"))
    deadline.on_expire(lambda: calls.append("b"))
    deadline.expire()
    deadline.expire()
    assert calls == ["a", "b"]
    assert deadline.expired and deadline.passed() and deadline.remaining() == 0.0


def test_callback_registered_after_expiry_runs_at_once() -> None:
    deadline = Deadline(100.0, Clock())
    deadline.expire()
    calls: list[str] = []
    deadline.on_expire(lambda: calls.append("late"))
    assert calls == ["late"]


def test_failing_callback_is_logged_and_others_run(tmp_path: Path) -> None:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) is not None
    try:
        deadline = Deadline(100.0, Clock())
        calls: list[str] = []

        def boom() -> None:
            raise OSError("socket gone")

        deadline.on_expire(boom)
        deadline.on_expire(lambda: calls.append("ok"))
        deadline.expire()
    finally:
        log_to_stderr()
    assert calls == ["ok"]
    text = path.read_text(encoding="utf-8")
    assert "deadline callback failed" in text and "OSError: socket gone" in text
