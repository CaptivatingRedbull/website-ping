from __future__ import annotations

import configparser
from pathlib import Path

APP_CONF = Path(__file__).absolute().parent.parent / "default" / "app.conf"


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
