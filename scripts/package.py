"""Build dist/<id>-<version>.tar.gz, ready for AppInspect or installing in Splunk."""

from __future__ import annotations

import configparser
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).absolute().parent.parent
APP_ITEMS = ("README.md", "README", "bin", "default", "metadata", "static")
EXECUTABLES = {"bin/web_ping.py"}


def read_app_conf() -> tuple[str, str]:
    """Return (package id, version) from default/app.conf."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(ROOT / "default" / "app.conf", encoding="utf-8")
    return parser.get("package", "id").strip(), parser.get(
        "launcher", "version"
    ).strip()


def build() -> Path:
    app_id, version = read_app_conf()

    def clean(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        path = PurePosixPath(info.name)
        if "__pycache__" in path.parts or path.suffix == ".pyc":
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
