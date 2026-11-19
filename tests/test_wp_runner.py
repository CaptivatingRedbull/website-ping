from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import wp_runner
from logger import StanzaLogger, log_to_stderr, setup_logging
from ping_check import CheckResult
from ping_config import Settings, build_settings
from wp_context import CheckContext, make_context
from wp_deadline import Phases
from wp_runner import (
    Checkpoints,
    Runner,
    is_due,
    non_deviated,
    read_input_config,
)

# ---- helpers ------------------------------------------------------------------


class Clock:
    """Wall and monotonic time under the test's control."""

    def __init__(self, wall: float = 1_000_000.0) -> None:
        self.wall: float = wall
        self.mono: float = 100.0

    def time(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds


class ManualExecutor:
    """Queues submitted calls; the test runs them with run_all()."""

    def __init__(self) -> None:
        self.pending: list[tuple[Callable[..., None], tuple[object, ...]]] = []
        self.shutdown_calls: list[tuple[bool, bool]] = []

    def submit(self, fn: Callable[..., None], /, *args: object) -> object:
        self.pending.append((fn, args))
        return None

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self.shutdown_calls.append((wait, cancel_futures))
        if cancel_futures:
            self.pending.clear()

    def run_all(self) -> int:
        count = 0
        while self.pending:
            fn, args = self.pending.pop(0)
            fn(*args)
            count += 1
        return count


def settings(name: str, interval: str = "60", **extra: str) -> Settings:
    built, _ = build_settings(
        f"web_ping://{name}",
        {"url": f"http://example.invalid/{name}", "interval": interval, **extra},
    )
    return built


def ok(context: CheckContext, _phases: Phases) -> CheckResult:
    return CheckResult(
        response_code=200, elapsed=0.1, finished=1.0, error=context.settings["name"]
    )


def render(stanza_settings: Settings, result: CheckResult) -> str:
    return f"{stanza_settings['name']}={result.response_code}\n"


@pytest.fixture
def log_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) is not None
    yield path
    log_to_stderr()


def log_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class Harness:
    def __init__(
        self,
        tmp_path: Path,
        stanzas: list[Settings],
        *,
        check: wp_runner.Check = ok,
        render_event: wp_runner.Render = render,
        write: wp_runner.Write | None = None,
        checkpoint_dir: Path | None = None,
        contexts: wp_runner.Contexts | None = None,
    ) -> None:
        self.clock: Clock = Clock()
        self.executor: ManualExecutor = ManualExecutor()
        self.events: list[str] = []
        self.checkpoints: Checkpoints = Checkpoints(
            str(checkpoint_dir or tmp_path / "checkpoints")
        )
        self.parent: int = 42
        self.runner: Runner = Runner(
            stanzas,
            check,
            render_event,
            write or self.events.append,
            self.checkpoints,
            contexts=contexts,
            clock=self.clock.time,
            monotonic=self.clock.monotonic,
            executor=self.executor,
            parent_pid=lambda: self.parent,
        )

    def cycle(self) -> int:
        """One tick, then run what it submitted."""
        self.runner.tick()
        return self.executor.run_all()


# ---- due rule and checkpoint value ---------------------------------------------


def test_never_run_is_due() -> None:
    assert is_due(None, 60, 0.0)


def test_due_only_strictly_after_interval() -> None:
    assert not is_due(1000.0, 60, 1060.0)
    assert is_due(1000.0, 60, 1060.001)


def test_non_deviated_first_run_is_now() -> None:
    assert non_deviated(None, 60, 5000.0) == 5000.0


def test_non_deviated_keeps_the_schedule() -> None:
    assert non_deviated(1000.0, 60, 1065.0) == 1060.0


def test_non_deviated_restarts_a_schedule_far_behind() -> None:
    assert non_deviated(1000.0, 60, 1121.0) == 1121.0
    assert non_deviated(1000.0, 60, 1120.0) == 1060.0  # derived == now - interval


# ---- checkpoints ---------------------------------------------------------------


def test_checkpoint_path_is_website_monitorings(tmp_path: Path) -> None:
    checkpoints = Checkpoints(str(tmp_path))
    digest = hashlib.sha224(b"web_ping://x").hexdigest()
    assert checkpoints.path_for("web_ping://x") == str(tmp_path / f"{digest}.json")


def test_checkpoint_round_trip_and_format(tmp_path: Path) -> None:
    checkpoints = Checkpoints(str(tmp_path / "new" / "dir"))
    checkpoints.save("web_ping://x", 1234.5)
    assert checkpoints.last_run("web_ping://x") == 1234.5
    path = Path(checkpoints.path_for("web_ping://x"))
    assert json.loads(path.read_text(encoding="utf-8")) == {"last_run": 1234.5}
    checkpoints.save("web_ping://x", 2000.0)
    assert checkpoints.last_run("web_ping://x") == 2000.0
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]


def test_checkpoint_written_by_website_monitoring_is_read(tmp_path: Path) -> None:
    checkpoints = Checkpoints(str(tmp_path))
    _ = Path(checkpoints.path_for("web_ping://x")).write_text(
        '{"last_run": 1700000000}'
    )
    assert checkpoints.last_run("web_ping://x") == 1700000000.0


@pytest.mark.parametrize(
    "content", ["", "{", "[]", '"x"', '{"other": 1}', '{"last_run": "1"}',
                '{"last_run": true}', '{"last_run": null}'],
)  # fmt: skip
def test_unusable_checkpoint_means_never_run(tmp_path: Path, content: str) -> None:
    checkpoints = Checkpoints(str(tmp_path))
    _ = Path(checkpoints.path_for("web_ping://x")).write_text(content)
    assert checkpoints.last_run("web_ping://x") is None


def test_missing_checkpoint_means_never_run(tmp_path: Path) -> None:
    assert Checkpoints(str(tmp_path / "absent")).last_run("web_ping://x") is None


def test_failed_save_keeps_old_file_and_leaves_no_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoints = Checkpoints(str(tmp_path))
    checkpoints.save("web_ping://x", 1.0)

    def fail(_src: str, _dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(wp_runner.os, "replace", fail)
    with pytest.raises(OSError):
        checkpoints.save("web_ping://x", 2.0)
    monkeypatch.undo()
    assert checkpoints.last_run("web_ping://x") == 1.0
    assert len(list(tmp_path.iterdir())) == 1


# ---- input configuration -------------------------------------------------------

SECRET = "s3cr3t-session-key"


def config_xml(*stanzas: str) -> str:
    body = "".join(
        f'<stanza name="web_ping://{name}" app="website_ping_inputs">'
        f'<param name="url"> http://example.invalid/{name} </param>'
        '<param name="interval">15m</param></stanza>'
        for name in stanzas
    )
    return (
        "<input><server_host>so1</server_host>"
        "<server_uri>https://127.0.0.1:8089</server_uri>"
        f"<session_key>{SECRET}</session_key>"
        "<checkpoint_dir>/opt/splunk/var/lib/splunk/modinputs/web_ping</checkpoint_dir>"
        f"<configuration>{body}</configuration></input>"
    )


@pytest.mark.parametrize("names", [(), ("a",), ("a", "b", "c")])
def test_read_input_config(names: tuple[str, ...]) -> None:
    config = read_input_config(config_xml(*names))
    assert config.server_host == "so1"
    assert config.server_uri == "https://127.0.0.1:8089"
    assert config.checkpoint_dir == "/opt/splunk/var/lib/splunk/modinputs/web_ping"
    assert config.session_key == SECRET
    assert list(config.stanzas) == [f"web_ping://{n}" for n in names]
    for name in names:
        assert config.stanzas[f"web_ping://{name}"] == {
            "url": f"http://example.invalid/{name}",
            "interval": "15m",
        }


def test_checkpoint_dir_is_required() -> None:
    with pytest.raises(ValueError, match="checkpoint_dir"):
        _ = read_input_config("<input><configuration/></input>")


def test_session_key_not_in_repr() -> None:
    assert SECRET not in repr(read_input_config(config_xml("a")))


# ---- scheduling ----------------------------------------------------------------


def test_first_run_immediately_then_after_interval(tmp_path: Path) -> None:
    h = Harness(tmp_path, [settings("a", "15m")])
    assert h.cycle() == 1
    assert h.events == ["a=200\n"]
    start = h.clock.wall
    assert h.checkpoints.last_run("web_ping://a") == start
    h.clock.advance(900)
    assert h.cycle() == 0  # exactly one interval: not due yet (strict <)
    h.clock.advance(0.5)
    assert h.cycle() == 1
    assert h.checkpoints.last_run("web_ping://a") == start + 900


def test_existing_checkpoint_is_respected(tmp_path: Path) -> None:
    checkpoints = Checkpoints(str(tmp_path / "checkpoints"))
    checkpoints.save("web_ping://a", Clock().wall - 30)
    h = Harness(tmp_path, [settings("a", "60")])
    assert h.cycle() == 0
    h.clock.advance(31)
    assert h.cycle() == 1


def test_never_two_checks_of_one_stanza(tmp_path: Path) -> None:
    h = Harness(tmp_path, [settings("a", "1")])
    h.runner.tick()
    h.clock.advance(10)
    h.runner.tick()
    assert len(h.executor.pending) == 1


def test_late_start_warns(tmp_path: Path, log_file: Path) -> None:
    h = Harness(tmp_path, [settings("a", "30")])
    h.runner.tick()
    h.clock.advance(45)
    _ = h.executor.run_all()
    assert "WARN stanza=web_ping://a v=" in log_text(log_file)
    assert "check started 45 s late" in log_text(log_file)
    h.runner.heartbeat()
    assert " late=1 events=1" in log_text(log_file)


def test_check_exception_does_not_stop_the_others(
    tmp_path: Path, log_file: Path
) -> None:
    def check(context: CheckContext, phases: Phases) -> CheckResult:
        if context.settings["name"] == "bad":
            raise RuntimeError("boom")
        return ok(context, phases)

    h = Harness(tmp_path, [settings("bad"), settings("good")], check=check)
    assert h.cycle() == 2
    assert h.events == ["good=200\n"]
    assert h.checkpoints.last_run("web_ping://bad") == h.clock.wall
    text = log_text(log_file)
    assert "stanza=web_ping://bad" in text and "RuntimeError: boom" in text
    assert h.cycle() == 0  # checkpointed, so it does not loop


def test_render_exception_is_checkpointed(tmp_path: Path) -> None:
    def broken(_settings: Settings, _result: CheckResult) -> str:
        raise ValueError("bad event")

    h = Harness(tmp_path, [settings("a")], render_event=broken)
    assert h.cycle() == 1
    assert h.events == []
    assert h.checkpoints.last_run("web_ping://a") == h.clock.wall
    assert not h.runner.stopping


@pytest.mark.parametrize("error", [BrokenPipeError(), ValueError("closed file")])
def test_closed_stdout_stops_without_checkpoint(
    tmp_path: Path, error: Exception
) -> None:
    def write(_event: str) -> None:
        raise error

    h = Harness(tmp_path, [settings("a"), settings("b")], write=write)
    h.runner.tick()
    _ = h.executor.run_all()
    assert h.runner.stopping
    assert h.checkpoints.last_run("web_ping://a") is None
    assert h.checkpoints.last_run("web_ping://b") is None
    assert h.runner.run() == "stdout closed"


def test_result_after_stop_is_neither_written_nor_checkpointed(tmp_path: Path) -> None:
    holder: list[Runner] = []

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        holder[0].stop("SIGTERM")
        return ok(context, phases)

    h = Harness(tmp_path, [settings("a")], check=check)
    holder.append(h.runner)
    assert h.cycle() == 1
    assert h.events == []
    assert h.checkpoints.last_run("web_ping://a") is None


def test_unsaved_checkpoint_is_logged_and_kept_in_memory(
    tmp_path: Path, log_file: Path
) -> None:
    blocker = tmp_path / "file"
    _ = blocker.write_text("")
    h = Harness(tmp_path, [settings("a")], checkpoint_dir=blocker / "checkpoints")
    assert h.cycle() == 1
    assert "cannot save checkpoint" in log_text(log_file)
    assert h.cycle() == 0


def test_shutdown_cancels_queued_checks(tmp_path: Path) -> None:
    h = Harness(tmp_path, [settings("a"), settings("b")])
    h.runner.tick()
    assert h.runner.shutdown(timeout=0) == 0
    assert h.executor.shutdown_calls == [(False, True)]
    assert h.executor.pending == []
    assert h.events == []


def test_parent_change_stops(tmp_path: Path, log_file: Path) -> None:
    h = Harness(tmp_path, [settings("a")])
    h.parent = 1
    h.runner.tick()
    assert h.runner.stopping
    assert h.runner.run() == "parent process gone"
    assert "parent process changed" in log_text(log_file)


def test_heartbeat_line(tmp_path: Path, log_file: Path) -> None:
    h = Harness(tmp_path, [settings("a"), settings("b")])
    _ = h.cycle()
    h.clock.advance(wp_runner.HEARTBEAT)
    h.runner.tick()  # heartbeat due; both stanzas not due again yet
    assert "INFO v=" in log_text(log_file)
    assert " heartbeat stanzas=2 in_flight=0 queued=0 late=0 events=2" in log_text(
        log_file
    )
    h.runner.heartbeat()
    assert log_text(log_file).rstrip().endswith("late=0 events=0")


# ---- check contexts --------------------------------------------------------------


class FakeContexts:
    """Contexts under the test's control: loaded or not, stanzas held back."""

    def __init__(self) -> None:
        self.loaded: bool = True
        self.held: set[str] = set()
        self.passes: int = 0
        self.body_length: int = 1000

    def ready(self) -> bool:
        self.passes += 1
        return self.loaded

    def context(self, settings: Settings, log: StanzaLogger) -> CheckContext | None:
        if settings["name"] in self.held:
            return None
        return make_context(settings, max_response_body_length=self.body_length)


def test_nothing_runs_until_the_configuration_is_loaded(
    tmp_path: Path, log_file: Path
) -> None:
    contexts = FakeContexts()
    contexts.loaded = False
    h = Harness(tmp_path, [settings("a")], contexts=contexts)
    assert h.cycle() == 0
    h.clock.advance(wp_runner.HEARTBEAT)
    h.runner.tick()
    assert " heartbeat stanzas=1 in_flight=0 queued=0 " in log_text(log_file)
    contexts.loaded = True
    assert h.cycle() == 1
    assert contexts.passes == 3


def test_stanza_without_context_is_skipped_without_checkpoint(tmp_path: Path) -> None:
    contexts = FakeContexts()
    contexts.held = {"a"}
    h = Harness(tmp_path, [settings("a"), settings("b")], contexts=contexts)
    assert h.cycle() == 1
    assert h.events == ["b=200\n"]
    assert h.checkpoints.last_run("web_ping://a") is None
    contexts.held = set()
    assert h.cycle() == 1
    assert h.events[-1] == "a=200\n"


def test_check_receives_the_context(tmp_path: Path) -> None:
    seen: list[CheckContext] = []

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        seen.append(context)
        return ok(context, phases)

    contexts = FakeContexts()
    contexts.body_length = 77
    h = Harness(tmp_path, [settings("a")], check=check, contexts=contexts)
    assert h.cycle() == 1
    assert [c.max_response_body_length for c in seen] == [77]
    assert seen[0].settings["stanza"] == "web_ping://a"


def test_without_contexts_checks_get_the_builtin_values(tmp_path: Path) -> None:
    seen: list[CheckContext] = []

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        seen.append(context)
        return ok(context, phases)

    h = Harness(tmp_path, [settings("a")], check=check)
    assert h.cycle() == 1
    assert seen == [make_context(settings("a"))]


# ---- threads, deadlines, stop --------------------------------------------------


def wait_until(condition: Callable[[], bool], timeout: float = 5) -> None:
    end = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < end, "condition not met in time"
        time.sleep(0.01)


def test_thread_limit_is_respected(tmp_path: Path) -> None:
    release = threading.Event()
    lock = threading.Lock()
    running = [0, 0]  # now, maximum

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        with lock:
            running[0] += 1
            running[1] = max(running)
        _ = release.wait(5)
        with lock:
            running[0] -= 1
        return ok(context, phases)

    events: list[str] = []
    runner = Runner(
        [settings(str(i)) for i in range(5)],
        check,
        render,
        events.append,
        Checkpoints(str(tmp_path)),
        thread_limit=2,
    )
    runner.tick()
    wait_until(lambda: running[0] == 2)
    time.sleep(0.1)
    assert running == [2, 2]
    release.set()
    wait_until(lambda: len(events) == 5)
    assert running[1] == 2
    assert runner.shutdown(timeout=1) == 0


def test_tick_expires_overdue_deadline(tmp_path: Path) -> None:
    clock = Clock()
    started = threading.Event()
    expired = threading.Event()

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        phases.start(context.settings["timeout"]).on_expire(expired.set)
        started.set()
        _ = expired.wait(5)
        return ok(context, phases)

    events: list[str] = []
    runner = Runner(
        [settings("a", timeout="5")],
        check,
        render,
        events.append,
        Checkpoints(str(tmp_path)),
        clock=clock.time,
        monotonic=clock.monotonic,
        executor=ThreadPoolExecutor(max_workers=1),
    )
    runner.tick()
    assert started.wait(5)  # pyright: ignore[reportPrivateUsage]
    clock.advance(4.9)
    runner.tick()
    assert not expired.is_set()
    clock.advance(0.2)
    runner.tick()
    assert expired.wait(1)
    wait_until(lambda: events == ["a=200\n"])
    assert runner.shutdown(timeout=1) == 0


def test_tick_expires_each_phase_at_its_own_time(tmp_path: Path) -> None:
    clock = Clock()
    probe_started, probe_ended = threading.Event(), threading.Event()
    request_started, request_ended = threading.Event(), threading.Event()

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        phases.start(5).on_expire(probe_ended.set)
        probe_started.set()
        _ = probe_ended.wait(5)
        phases.start(5).on_expire(request_ended.set)
        request_started.set()
        _ = request_ended.wait(5)
        return ok(context, phases)

    events: list[str] = []
    runner = Runner(
        [settings("a", timeout="5")],
        check,
        render,
        events.append,
        Checkpoints(str(tmp_path)),
        clock=clock.time,
        monotonic=clock.monotonic,
        executor=ThreadPoolExecutor(max_workers=1),
    )
    runner.tick()
    assert probe_started.wait(5)
    clock.advance(5)
    runner.tick()
    assert probe_ended.wait(1)
    assert request_started.wait(5)
    clock.advance(4.9)
    runner.tick()
    assert not request_ended.is_set()
    clock.advance(0.1)
    runner.tick()
    assert request_ended.wait(1)
    wait_until(lambda: events == ["a=200\n"])
    assert runner.shutdown(timeout=1) == 0


def test_shutdown_expires_running_checks_and_waits(tmp_path: Path) -> None:
    def check(context: CheckContext, phases: Phases) -> CheckResult:
        done = threading.Event()
        phases.start(context.settings["timeout"]).on_expire(done.set)
        _ = done.wait(5)
        return ok(context, phases)

    events: list[str] = []
    runner = Runner(
        [settings("a")], check, render, events.append, Checkpoints(str(tmp_path))
    )
    runner.tick()
    wait_until(lambda: runner._deadlines != {})  # pyright: ignore[reportPrivateUsage]
    started = time.monotonic()
    assert runner.shutdown(timeout=2) == 0
    assert time.monotonic() - started < 1
    assert events == []


def test_shutdown_gives_up_after_timeout(tmp_path: Path) -> None:
    release = threading.Event()

    def check(context: CheckContext, phases: Phases) -> CheckResult:
        _ = release.wait(5)  # ignores the deadline
        return ok(context, phases)

    runner = Runner(
        [settings("a")], check, render, lambda _e: None, Checkpoints(str(tmp_path))
    )
    runner.tick()
    wait_until(lambda: runner._deadlines != {})  # pyright: ignore[reportPrivateUsage]
    started = time.monotonic()
    assert runner.shutdown(timeout=0.3) == 1
    assert 0.25 < time.monotonic() - started < 1
    release.set()


def test_signal_stops_run_quickly(tmp_path: Path) -> None:
    runner = Runner([], ok, render, lambda _e: None, Checkpoints(str(tmp_path)))
    timer = threading.Timer(0.2, runner.on_signal, (signal.SIGTERM, None))
    timer.start()
    started = time.monotonic()
    assert runner.run() == "SIGTERM"
    assert time.monotonic() - started < 0.2 + 2 * wp_runner.POLL + 0.2
    runner.on_signal(signal.SIGTERM, None)  # repeated signals are harmless
    assert runner.run() == "SIGTERM"


def test_failing_pass_does_not_end_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_file: Path
) -> None:
    runner = Runner([], ok, render, lambda _e: None, Checkpoints(str(tmp_path)))
    calls = [0]

    def tick() -> None:
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("bad pass")
        runner.on_signal(signal.SIGINT, None)

    monkeypatch.setattr(wp_runner, "TICK", 0.05)
    monkeypatch.setattr(runner, "tick", tick)
    assert runner.run() == "SIGINT"
    assert calls[0] == 2
    assert "scheduler pass failed" in log_text(log_file)
    assert "RuntimeError: bad pass" in log_text(log_file)


def test_no_stanzas_runs_idle(tmp_path: Path) -> None:
    runner = Runner([], ok, render, lambda _e: None, Checkpoints(str(tmp_path)))
    runner.tick()
    assert not runner.stopping
    assert not os.listdir(tmp_path)
