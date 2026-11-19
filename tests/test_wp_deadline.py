from __future__ import annotations

from pathlib import Path

from logger import log_to_stderr, setup_logging
from wp_deadline import Deadline, Phases


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


def test_phases_start_one_after_the_other() -> None:
    clock = Clock()
    phases = Phases(clock)
    assert phases.current is None
    phases.expire_overdue()  # nothing started yet
    probe = phases.start(5)
    assert phases.current is probe and probe.at == 15.0
    clock.now = 12.0
    request = phases.start(5)
    assert phases.current is request and request.at == 17.0
    assert not probe.expired


def test_expire_overdue_only_ends_the_current_phase_when_due() -> None:
    clock = Clock()
    phases = Phases(clock)
    deadline = phases.start(5)
    clock.now = 14.9
    phases.expire_overdue()
    assert not deadline.expired
    clock.now = 15.0
    phases.expire_overdue()
    assert deadline.expired
    later = phases.start(5)
    assert not later.expired


def test_stop_ends_the_current_and_every_later_phase() -> None:
    phases = Phases(Clock())
    stopped: list[str] = []
    phases.start(5).on_expire(lambda: stopped.append("probe"))
    phases.stop()
    assert stopped == ["probe"]
    assert phases.start(5).expired


def test_stop_before_the_first_phase() -> None:
    phases = Phases(Clock())
    phases.stop()
    assert phases.start(5).expired
