from __future__ import annotations

import configparser
import platform
import ssl
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


def runtime_versions() -> str:
    """Interpreter and OpenSSL versions as log fields.

    Splunk picks the interpreter from python.required, so the log is the only place
    that shows which one runs: python=3.13.11 openssl="OpenSSL 3.5.9 29 Sep 2026".
    """
    return f'python={platform.python_version()} openssl="{ssl.OPENSSL_VERSION}"'
