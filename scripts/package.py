"""Build dist/<id>-<version>.tar.gz, ready for AppInspect or installing in Splunk."""

from __future__ import annotations

import configparser
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).absolute().parent.parent
APP_ITEMS = ("LICENSE", "README.md", "README", "bin", "default", "metadata", "static")
EXCLUDED_NAMES = {"__pycache__", ".DS_Store"}
EXCLUDED_SUFFIXES = {".pyc", ".orig", ".swp"}
EXECUTABLES = {"bin/web_ping.py"}


def read_app_conf() -> tuple[str, str]:
    """Return (package id, version) from default/app.conf."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(ROOT / "default" / "app.conf", encoding="utf-8")
    return (
        parser.get("package", "id").strip(),
        parser.get("launcher", "version").strip(),
    )


def check_app_items() -> None:
    """Stop with a clear message when an app item is missing (e.g. on a fresh clone)."""
    for item in APP_ITEMS:
        if not (ROOT / item).exists():
            raise SystemExit(f"missing app item: {item}")


def build() -> Path:
    check_app_items()
    app_id, version = read_app_conf()

    def clean(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        path = PurePosixPath(info.name)
        if EXCLUDED_NAMES.intersection(path.parts) or path.suffix in EXCLUDED_SUFFIXES:
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        relative = path.relative_to(app_id).as_posix()
        info.mode = 0o755 if info.isdir() or relative in EXECUTABLES else 0o644
        return info

    target = ROOT / "dist" / f"{app_id}-{version}.tar.gz"
    target.parent.mkdir(exist_ok=True)
    with tarfile.open(target, "w:gz") as tar:
        for item in APP_ITEMS:
            tar.add(ROOT / item, arcname=f"{app_id}/{item}", filter=clean)
    return target


if __name__ == "__main__":
    print(build())
