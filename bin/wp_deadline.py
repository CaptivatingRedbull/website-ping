"""The time budget of one check."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from logger import process_log


class Deadline:
    """When one check must end, on the monotonic clock.

    The scheduler calls expire() once the time is up or the process stops; it runs
    every callback registered with on_expire, once. A check registers callbacks that
    unblock what it is waiting for, and treats any failure after expiry as a
    timeout.
    """

    def __init__(self, at: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.at: float = at
        self._clock: Callable[[], float] = clock
        self._lock: threading.Lock = threading.Lock()
        self._expired: bool = False
        self._callbacks: list[Callable[[], None]] = []

    @classmethod
    def after(
        cls, seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> Deadline:
        return cls(clock() + seconds, clock)

    @property
    def expired(self) -> bool:
        """expire() has been called."""
        return self._expired

    def remaining(self) -> float:
        """Seconds left, 0 once the time is up or the deadline expired."""
        if self._expired:
            return 0.0
        return max(0.0, self.at - self._clock())

    def passed(self) -> bool:
        """The time is up or the deadline expired."""
        return self._expired or self._clock() >= self.at

    def on_expire(self, callback: Callable[[], None]) -> None:
        """Run callback on expiry; at once if the deadline has already expired."""
        with self._lock:
            if not self._expired:
                self._callbacks.append(callback)
                return
        _call(callback)

    def expire(self) -> None:
        with self._lock:
            if self._expired:
                return
            self._expired = True
            callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks:
            _call(callback)


def _call(callback: Callable[[], None]) -> None:
    try:
        callback()
    except Exception:  # noqa: BLE001 - one failing callback must not stop the others
        process_log.exception("deadline callback failed")
