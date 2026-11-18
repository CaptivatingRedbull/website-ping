"""Scheduling of every web_ping stanza in one process.

splunkd starts web_ping.py once with all enabled stanzas (single-instance scheme)
and does not start it again after it exits. The Runner decides when each stanza is
due, runs the checks on a thread pool, writes their events and keeps one checkpoint
file per stanza in Website Monitoring 2.9.7's format, so schedules survive restarts
and a migration from that app.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from types import FrameType
from typing import Protocol, cast

from logger import StanzaLogger, process_log, stanza_logger
from ping_check import CheckResult
from ping_config import Settings
from wp_context import BuiltinContexts, CheckContext
from wp_deadline import Deadline
from wp_splunk import DEFAULT_THREAD_LIMIT

TICK = 1.0
"""Seconds between scheduling passes."""
POLL = 0.1
"""Seconds between looks at the stop flag, so a SIGTERM is noticed at once."""
HEARTBEAT = 60.0
STOP_WAIT = 2.0
"""Seconds to wait for running checks after a stop. splunkd kills the input about
5 s after its first SIGTERM."""


@dataclass(frozen=True)
class InputConfig:
    """What splunkd sends on stdin. session_key is kept out of repr()."""

    server_host: str
    server_uri: str
    checkpoint_dir: str
    stanzas: Mapping[str, Mapping[str, str]]
    """Stanza name (web_ping://<name>) to its params, in the order received."""
    session_key: str = field(repr=False)


def read_input_config(xml_text: str) -> InputConfig:
    """Parse the input configuration XML. Raises ET.ParseError for malformed XML and
    ValueError without a checkpoint_dir (checkpoints would land in the working
    directory)."""
    root = ET.fromstring(xml_text)
    checkpoint_dir = (root.findtext("checkpoint_dir") or "").strip()
    if not checkpoint_dir:
        raise ValueError("no checkpoint_dir in the input configuration")
    stanzas: dict[str, dict[str, str]] = {}
    for stanza in root.iterfind("configuration/stanza"):
        name = stanza.get("name")
        if not name:
            continue
        stanzas[name] = {
            key: (param.text or "").strip()
            for param in stanza.iterfind("param")
            if (key := param.get("name"))
        }
    return InputConfig(
        server_host=(root.findtext("server_host") or "").strip(),
        server_uri=(root.findtext("server_uri") or "").strip(),
        checkpoint_dir=checkpoint_dir,
        stanzas=stanzas,
        session_key=(root.findtext("session_key") or "").strip(),
    )


class Checkpoints:
    """One JSON file {"last_run": <epoch seconds>} per stanza, named by the SHA-224
    of the full stanza name, as Website Monitoring 2.9.7 wrote them."""

    def __init__(self, directory: str) -> None:
        self.directory: str = directory

    def path_for(self, stanza: str) -> str:
        digest = hashlib.sha224(stanza.encode("utf-8")).hexdigest()
        return os.path.join(self.directory, digest + ".json")

    def last_run(self, stanza: str) -> float | None:
        """None when there is no usable checkpoint (missing, unreadable, invalid)."""
        try:
            with open(self.path_for(stanza), encoding="utf-8") as stream:
                data: object = json.load(stream)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        value = cast("dict[str, object]", data).get("last_run")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    def save(self, stanza: str, last_run: float) -> None:
        """Write atomically: the process can be killed at any moment, and a reader
        then sees the old file or the new one, never half of one."""
        os.makedirs(self.directory, exist_ok=True)
        handle, temporary = tempfile.mkstemp(
            prefix=".checkpoint-", suffix=".tmp", dir=self.directory
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump({"last_run": last_run}, stream)
            os.replace(temporary, self.path_for(stanza))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise


def is_due(last_run: float | None, interval: float, now: float) -> bool:
    """Website Monitoring's rule: never run, or more than interval since last_run."""
    return last_run is None or last_run + interval < now


def non_deviated(last_ran: float | None, interval: float, now: float) -> float:
    """The last_run to save after a check, so the processing time does not shift the
    schedule. A schedule more than one interval behind restarts at now."""
    if last_ran is None:
        return now
    derived = last_ran + interval
    if derived < now - interval:
        return now
    return derived


@dataclass
class _Stanza:
    settings: Settings
    log: StanzaLogger
    last_run: float | None
    busy: bool = False
    """Queued or running; a stanza never has two checks at once."""


class Executor(Protocol):
    """The part of concurrent.futures.Executor the Runner uses."""

    def submit(
        self, fn: Callable[[_Stanza, CheckContext, float], None], /, *args: object
    ) -> object: ...
    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None: ...


class Contexts(Protocol):
    """Where the scheduler gets the context of each check from."""

    def ready(self) -> bool:
        """Called once per scheduling pass. False: no check may start now."""
        ...

    def context(self, settings: Settings, log: StanzaLogger) -> CheckContext | None:
        """The context for a check of this stanza; None: do not run it now."""
        ...


Check = Callable[[CheckContext, Deadline], CheckResult]
Render = Callable[[Settings, CheckResult], str]
Write = Callable[[str], None]


class Runner:
    """Runs every stanza on its interval until stopped.

    check runs one check; render turns its result into event XML; write sends
    that to splunkd. A write that fails because stdout is closed stops the runner
    (splunkd closes stdout when it stops the input).
    """

    def __init__(
        self,
        settings: Sequence[Settings],
        check: Check,
        render: Render,
        write: Write,
        checkpoints: Checkpoints,
        *,
        thread_limit: int = DEFAULT_THREAD_LIMIT,
        contexts: Contexts | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        executor: Executor | None = None,
        parent_pid: Callable[[], int] = os.getppid,
    ) -> None:
        self._stanzas: list[_Stanza] = [
            _Stanza(
                s,
                stanza_logger(s["stanza"], s["log_level"]),
                checkpoints.last_run(s["stanza"]),
            )
            for s in settings
        ]
        self._check: Check = check
        self._contexts: Contexts = contexts or BuiltinContexts()
        self._render: Render = render
        self._write: Write = write
        self._checkpoints: Checkpoints = checkpoints
        self._clock: Callable[[], float] = clock
        self._monotonic: Callable[[], float] = monotonic
        self._executor: Executor = executor or ThreadPoolExecutor(
            max_workers=thread_limit, thread_name_prefix="web_ping"
        )
        self._parent_pid: Callable[[], int] = parent_pid
        self._first_parent: int = parent_pid()
        self._lock: threading.Lock = threading.Lock()
        self._idle: threading.Condition = threading.Condition(self._lock)
        self._write_lock: threading.Lock = threading.Lock()
        self._stop: threading.Event = threading.Event()
        self._stop_reason: str = ""
        self._signal: int | None = None
        self._deadlines: dict[str, Deadline] = {}
        self._queued: int = 0
        self._running: int = 0
        self._late: int = 0
        self._events: int = 0
        self._next_heartbeat: float = monotonic() + HEARTBEAT

    # ---- stopping ------------------------------------------------------------

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def stop(self, reason: str) -> None:
        """Stop scheduling. Not for signal handlers: use on_signal there."""
        with self._lock:
            if not self._stop_reason:
                self._stop_reason = reason
        self._stop.set()

    def on_signal(self, signum: int, _frame: FrameType | None) -> None:
        """Signal handler. Only stores the signal: taking a lock here could deadlock
        if the signal interrupts the main thread while it holds that lock. The main
        loop notices within POLL seconds. Safe to receive several times."""
        self._signal = signum

    # ---- scheduling ----------------------------------------------------------

    def tick(self) -> None:
        """One scheduling pass: expire overdue deadlines, submit due stanzas (once
        the configuration is loaded), heartbeat, parent check."""
        self._expire_deadlines(only_overdue=True)
        if self._contexts.ready():
            self._submit_due()
        if self.stopping:
            return
        if self._monotonic() >= self._next_heartbeat:
            self.heartbeat()
        if self._parent_pid() != self._first_parent:
            process_log.warning("splunkd is gone (parent process changed)")
            self.stop("parent process gone")

    def _submit_due(self) -> None:
        now = self._clock()
        for entry in self._stanzas:
            if self.stopping:
                return
            with self._lock:
                if entry.busy or not is_due(
                    entry.last_run, entry.settings["interval"], now
                ):
                    continue
            # Not run and not checkpointed: asked again at the next pass.
            context = self._contexts.context(entry.settings, entry.log)
            if context is None:
                continue
            with self._lock:
                entry.busy = True
                self._queued += 1
            try:
                _ = self._executor.submit(
                    self._execute, entry, context, self._monotonic()
                )
            except BaseException:
                with self._lock:
                    entry.busy = False
                    self._queued -= 1
                raise

    def heartbeat(self) -> None:
        with self._lock:
            running, queued, late, events = (
                self._running,
                self._queued,
                self._late,
                self._events,
            )
            self._late = 0
            self._events = 0
            self._next_heartbeat = self._monotonic() + HEARTBEAT
        process_log.info(
            "heartbeat stanzas=%d in_flight=%d queued=%d late=%d events=%d",
            len(self._stanzas),
            running,
            queued,
            late,
            events,
        )

    def run(self) -> str:
        """Schedule until stopped; returns the reason. Every pass is guarded: the
        process must not end over one failure, since nothing would restart it."""
        next_tick = self._monotonic()
        while True:
            if self._signal is not None:
                self.stop(_signal_name(self._signal))
            if self.stopping:
                return self._stop_reason
            if self._monotonic() >= next_tick:
                next_tick = self._monotonic() + TICK
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 - see docstring
                    process_log.exception("scheduler pass failed")
            _ = self._stop.wait(POLL)

    def shutdown(self, timeout: float = STOP_WAIT) -> int:
        """Cancel queued checks, expire running ones and wait up to timeout for them.
        Returns the number of checks still running. Their results are discarded."""
        self.stop("shutdown")
        self._expire_deadlines(only_overdue=False)
        self._executor.shutdown(wait=False, cancel_futures=True)
        end = self._monotonic() + timeout
        with self._idle:
            while self._running:
                left = end - self._monotonic()
                if left <= 0:
                    break
                _ = self._idle.wait(left)
            return self._running

    def _expire_deadlines(self, *, only_overdue: bool) -> None:
        with self._lock:
            deadlines = list(self._deadlines.values())
        for deadline in deadlines:
            if not deadline.expired and (not only_overdue or deadline.passed()):
                deadline.expire()

    # ---- one check (worker thread) -------------------------------------------

    def _execute(self, entry: _Stanza, context: CheckContext, submitted: float) -> None:
        started = self._monotonic()
        with self._lock:
            self._queued -= 1
            self._running += 1
        try:
            if self.stopping:
                return
            waited = started - submitted
            if waited > max(entry.settings["interval"], TICK):
                entry.log.warning("check started %d s late", round(waited))
                with self._lock:
                    self._late += 1
            self._run_check(entry, context, started)
        except Exception:  # a worker must never die silently
            entry.log.exception("check could not run")
        finally:
            with self._idle:
                self._running -= 1
                entry.busy = False
                self._idle.notify_all()

    def _run_check(self, entry: _Stanza, context: CheckContext, started: float) -> None:
        settings = entry.settings
        stanza = settings["stanza"]
        last_ran = entry.last_run
        deadline = Deadline(started + settings["timeout"], self._monotonic)
        with self._lock:
            self._deadlines[stanza] = deadline
        try:
            result: CheckResult | None = self._check(context, deadline)
        except Exception:  # checkpoint anyway, so it does not loop
            entry.log.exception("check failed unexpectedly, no event written")
            result = None
        finally:
            with self._lock:
                _ = self._deadlines.pop(stanza, None)
        if self.stopping:
            # stdout is closed by now; without a checkpoint it runs after the restart.
            return
        if result is not None:
            try:
                event = self._render(settings, result)
            except Exception:  # checkpoint anyway, so it does not loop
                entry.log.exception("event could not be built, no event written")
            else:
                if not self._write_event(entry, event):
                    return
        self._save(entry, last_ran)

    def _write_event(self, entry: _Stanza, event: str) -> bool:
        with self._write_lock:
            if self.stopping:
                return False
            try:
                self._write(event)
            except (OSError, ValueError) as exc:
                # BrokenPipeError, or ValueError for a closed file: splunkd is
                # stopping the input.
                entry.log.warning("event not written, stdout closed (%s)", exc)
                self.stop("stdout closed")
                return False
        with self._lock:
            self._events += 1
        return True

    def _save(self, entry: _Stanza, last_ran: float | None) -> None:
        stanza = entry.settings["stanza"]
        now = self._clock()
        last_run = non_deviated(last_ran, entry.settings["interval"], now)
        if last_ran is not None and last_run == now:
            entry.log.info(
                "previous run too far in the past (gap=%ds), some runs were missed",
                round(now - last_ran),
            )
        try:
            self._checkpoints.save(stanza, last_run)
        except OSError as exc:
            entry.log.error(
                "cannot save checkpoint in %s: %s", self._checkpoints.directory, exc
            )
        with self._lock:
            entry.last_run = last_run


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"
