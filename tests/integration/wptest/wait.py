"""One polling helper for every stage, reporting the last stage reached on timeout."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

BUILD = "build"
HEALTHY = "healthy"
PROBE = "probe"
INSTALL = "install"
REGISTERED = "input registered"
STARTED = "script started"
INDEXED = "event indexed"
SEARCH_HEAD = "event visible on the search head"


class StageError(AssertionError):
    """A stage did not complete. The message names it and the last stage reached."""


class Stages:
    """The stages one stack has passed, in order."""

    def __init__(self) -> None:
        self.passed: list[str] = []

    def reached(self, stage: str) -> None:
        if stage not in self.passed:
            self.passed.append(stage)

    @property
    def last(self) -> str:
        return self.passed[-1] if self.passed else "none"

    def fail(self, stage: str, detail: str) -> StageError:
        return StageError(
            f"stage '{stage}' failed: {detail} (last stage reached: {self.last})"
        )


def wait_for(
    stage: str,
    check: Callable[[], T | None],
    timeout: float,
    stages: Stages,
    interval: float = 5.0,
) -> T:
    """Call check until it returns something other than None, or raise StageError.

    Exceptions from check count as "not yet" and the last one is reported.
    """
    deadline = time.monotonic() + timeout
    last = "no result"
    while True:
        try:
            result = check()
        except Exception as exc:  # noqa: BLE001 - reported on timeout
            result = None
            last = f"{type(exc).__name__}: {exc}"[:500]
        if result is not None:
            stages.reached(stage)
            return result
        if time.monotonic() >= deadline:
            raise stages.fail(stage, f"not done after {timeout:.0f} s, last: {last}")
        time.sleep(interval)
