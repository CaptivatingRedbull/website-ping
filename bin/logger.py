from __future__ import annotations

import configparser
import logging
import sys
from pathlib import Path

from compat import override

logging.addLevelName(logging.WARNING, "WARN")

LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
}

APP_CONF = Path(__file__).absolute().parent.parent / "default" / "app.conf"

log: logging.Logger = logging.getLogger("web_ping")


def read_app_version(path: str | Path = APP_CONF) -> str:
    """Return [launcher] version from app.conf, or 'unknown'. Never raises."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    try:
        _ = parser.read(path, encoding="utf-8")
        return parser.get("launcher", "version").strip() or "unknown"
    except (configparser.Error, OSError, ValueError):
        return "unknown"


APP_VERSION = read_app_version()


class OneLineFormatter(logging.Formatter):
    """Keep every record on one line so tracebacks stay in one splunkd.log entry."""

    @override
    def format(self, record: logging.LogRecord) -> str:
        record.version = "" if record.levelno == logging.INFO else f"v={APP_VERSION} "
        if record.levelno == logging.DEBUG:
            record.levelname = "INFO"
            record.msg = f"[debug] {record.msg}"
        return super().format(record).replace("\n", " | ")


def setup_logging(level_name: str = "INFO", stanza: str | None = None) -> bool:
    """Configure logging to stderr. Returns False if level_name was invalid."""
    level = LOG_LEVELS.get(level_name.strip().upper())
    prefix = f"stanza={stanza.replace('%', '%%')} " if stanza else ""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        OneLineFormatter("%(levelname)s " + prefix + "%(version)s%(message)s")
    )
    log.handlers[:] = [handler]
    log.setLevel(level if level is not None else logging.INFO)
    log.propagate = False
    return level is not None
