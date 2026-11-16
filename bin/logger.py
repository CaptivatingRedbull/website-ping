"""Logging for the input.

Records go to $SPLUNK_HOME/var/log/splunk/website_ping.log, which Splunk indexes
into _internal. splunkd.log (the input's stderr) only gets the lines marked with
CONSOLE, everything logged before the file is open, and everything if the file
cannot be opened.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from collections.abc import Mapping, MutableMapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from compat import override
from wp_version import APP_VERSION

logging.addLevelName(logging.WARNING, "WARN")

LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
}

LOG_FILE_NAME = "website_ping.log"
MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5

CONSOLE: Mapping[str, object] = {"console": True}
"""Pass as extra= for a line that splunkd.log should show as well."""

log: logging.Logger = logging.getLogger("web_ping")

if TYPE_CHECKING:
    _Adapter = logging.LoggerAdapter[logging.Logger]
else:
    _Adapter = logging.LoggerAdapter


def level_number(name: str) -> int:
    """The logging level for DEBUG, INFO, WARN or ERROR; INFO for anything else."""
    return LOG_LEVELS.get(name.strip().upper(), logging.INFO)


def _quoted(text: str) -> str:
    """A stanza name as a log field value, quoted when it contains a space or quote."""
    if text and not any(c.isspace() or c == '"' for c in text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _stanza_field(record: logging.LogRecord) -> str:
    stanza: object = getattr(record, "stanza", None)
    return f"stanza={_quoted(stanza)} " if isinstance(stanza, str) else ""


def _one_line(text: str) -> str:
    return " | ".join(text.splitlines())


class FileFormatter(logging.Formatter):
    """2026-11-16 11:34:00,123 +0100 INFO stanza=web_ping://x v=1.0.0 message

    One line per record (tracebacks joined with " | "), so every line is one
    event with a timestamp Splunk recognises, including the UTC offset.
    """

    @override
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        moment = datetime.fromtimestamp(record.created).astimezone()
        return (
            f"{moment.strftime('%Y-%m-%d %H:%M:%S')},{int(record.msecs):03d}"
            f" {moment.strftime('%z')}"
        )

    @override
    def format(self, record: logging.LogRecord) -> str:
        text = (
            f"{self.formatTime(record)} {record.levelname} {_stanza_field(record)}"
            f"v={APP_VERSION} {record.getMessage()}"
        )
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        if record.stack_info:
            text += "\n" + self.formatStack(record.stack_info)
        return _one_line(text)


class StderrFormatter(logging.Formatter):
    """INFO stanza=web_ping://x message, as splunkd.log expects it.

    splunkd adds its own timestamp and drops DEBUG lines, so DEBUG is written as
    "INFO [debug]". The version is added to every line that is not INFO.
    """

    @override
    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        message = record.getMessage()
        if record.levelno == logging.DEBUG:
            level, message = "INFO", f"[debug] {message}"
        version = "" if record.levelno == logging.INFO else f"v={APP_VERSION} "
        text = f"{level} {_stanza_field(record)}{version}{message}"
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        return _one_line(text)


class StderrHandler(logging.Handler):
    """Writes to whatever sys.stderr is at the time of the record."""

    @override
    def emit(self, record: logging.LogRecord) -> None:
        try:
            _ = sys.stderr.write(self.format(record) + "\n")
            sys.stderr.flush()
        except Exception:  # noqa: BLE001 - logging must never raise into the caller
            self.handleError(record)


def _console_only(record: logging.LogRecord) -> bool:
    return bool(getattr(record, "console", False))


class StanzaLogger(_Adapter):
    """Logs with stanza=<name> on every line and drops records below the stanza's
    log_level. stanza None is for lines about the whole process."""

    def __init__(self, stanza: str | None, level: int = logging.INFO) -> None:
        super().__init__(log, {})
        self.stanza: str | None = stanza
        self.level: int = level

    @override
    def isEnabledFor(self, level: int) -> bool:
        return level >= self.level and self.logger.isEnabledFor(level)

    @override
    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        extra: dict[str, object] = dict(kwargs.get("extra") or {})
        if self.stanza is not None:
            extra["stanza"] = self.stanza
        kwargs["extra"] = extra
        return msg, kwargs


def stanza_logger(stanza: str | None, level_name: str = "INFO") -> StanzaLogger:
    return StanzaLogger(stanza, level_number(level_name))


process_log: StanzaLogger = StanzaLogger(None)
"""Lines about the process as a whole (start, stop, configuration errors)."""


def log_file_path(environ: Mapping[str, str] = os.environ) -> str | None:
    """$SPLUNK_HOME/var/log/splunk/website_ping.log, or None without SPLUNK_HOME."""
    home = environ.get("SPLUNK_HOME", "").strip()
    if not home:
        return None
    return os.path.join(home, "var", "log", "splunk", LOG_FILE_NAME)


def _set_handlers(handlers: list[logging.Handler]) -> None:
    old = log.handlers[:]
    log.handlers[:] = handlers
    for handler in old:
        if handler not in handlers:
            handler.close()


def _stderr_handler(console_only: bool) -> StderrHandler:
    handler = StderrHandler()
    handler.setFormatter(StderrFormatter())
    if console_only:
        handler.addFilter(_console_only)
    return handler


def log_to_stderr() -> None:
    """Every record to stderr: the state before setup_logging and its fallback."""
    _set_handlers([_stderr_handler(console_only=False)])


def setup_logging(
    path: str | None = None,
    *,
    max_bytes: int = MAX_BYTES,
    backup_count: int = BACKUP_COUNT,
) -> str | None:
    """Log to the rotating file (default: log_file_path()) and CONSOLE lines to stderr.

    Returns the file's path, or None if it cannot be used; then every record goes to
    stderr and one ERROR line says why.
    """
    path = path or log_file_path()
    if path is None:
        log_to_stderr()
        process_log.error("SPLUNK_HOME is not set, logging to stderr")
        return None
    try:
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
    except OSError as exc:
        log_to_stderr()
        process_log.error(
            "cannot open log file %s (%s), logging to stderr",
            path,
            exc.strerror or exc,
        )
        return None
    handler.setFormatter(FileFormatter())
    _set_handlers([handler, _stderr_handler(console_only=True)])
    return path


def flush_logging() -> None:
    """Flush every handler; needed before os._exit, which skips logging's cleanup."""
    for handler in log.handlers:
        handler.flush()


log.setLevel(logging.DEBUG)
log.propagate = False
log_to_stderr()
