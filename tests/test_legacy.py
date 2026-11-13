"""Building Website Monitoring 2.9.7 from its tag archive (wptest/legacy.py)."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from wptest import legacy

ROOT = "splunk-website-monitoring-2.9.7"
APP_CONF = """\
[launcher]
version = ${value.version.number}

[install]
build = ${value.build.number}
# Last commit: ${value.build.date}
python.version = python3
"""


def tag_archive(
    path: Path, members: dict[str, bytes], commit: str = legacy.LEGACY_COMMIT
) -> Path:
    with tarfile.open(
        path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}
    ) as tar:
        for folder in (ROOT, f"{ROOT}/src", f"{ROOT}/src/bin", f"{ROOT}/src/default"):
            info = tarfile.TarInfo(folder)
            info.type = tarfile.DIRTYPE
            info.mode = 0o775
            tar.addfile(info)
        for name, data in members.items():
            info = tarfile.TarInfo(f"{ROOT}/{name}")
            info.size = len(data)
            info.mode = 0o664
            tar.addfile(info, io.BytesIO(data))
    return path


def test_release_app_conf() -> None:
    assert legacy.release_app_conf(APP_CONF) == (
        "[launcher]\nversion = 2.9.7\n\n[install]\nbuild = 0\npython.version = python3\n"
    )


def test_build_takes_src_with_modes(tmp_path: Path) -> None:
    source = tag_archive(
        tmp_path / "tag.tar.gz",
        {
            "src/default/app.conf": APP_CONF.encode(),
            "src/bin/web_ping.py": b"print()\n",
            "src/bin/modular_input.zip": b"PK",
            "build.xml": b"<project/>",
        },
    )
    package = legacy.build_legacy_package(source, tmp_path / "out.tar.gz")
    with tarfile.open(package) as tar:
        modes = {m.name: (m.mode, m.uid) for m in tar.getmembers()}
        app_conf = tar.extractfile("website_monitoring/default/app.conf")
        assert app_conf is not None
        assert b"version = 2.9.7" in app_conf.read()
    assert modes == {
        "website_monitoring": (0o755, 0),
        "website_monitoring/bin": (0o755, 0),
        "website_monitoring/default": (0o755, 0),
        "website_monitoring/default/app.conf": (0o644, 0),
        "website_monitoring/bin/web_ping.py": (0o755, 0),
        "website_monitoring/bin/modular_input.zip": (0o644, 0),
    }
    again = legacy.build_legacy_package(source, tmp_path / "again.tar.gz")
    assert again.read_bytes() == package.read_bytes()


def test_build_refuses_links(tmp_path: Path) -> None:
    path = tmp_path / "tag.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(f"{ROOT}/src/bin/evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(legacy.LegacyError):
        legacy.build_legacy_package(path, tmp_path / "out.tar.gz")


def cached(tmp_path: Path, commit: str = legacy.LEGACY_COMMIT) -> tuple[Path, str]:
    path = tmp_path / f"splunk-website-monitoring-{legacy.LEGACY_VERSION}.tar.gz"
    tag_archive(path, {"src/default/app.conf": APP_CONF.encode()}, commit)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_download_uses_the_cache_and_checks_the_pin(tmp_path: Path) -> None:
    path, digest = cached(tmp_path)
    assert legacy.download(tmp_path, pinned=digest) == path
    with pytest.raises(legacy.LegacyError, match=digest):
        legacy.download(tmp_path, pinned="")
    with pytest.raises(legacy.LegacyError, match="pinned"):
        legacy.download(tmp_path, pinned="0" * 64)


def test_download_checks_the_commit(tmp_path: Path) -> None:
    _, digest = cached(tmp_path, commit="0" * 40)
    with pytest.raises(legacy.LegacyError, match="commit"):
        legacy.download(tmp_path, pinned=digest)
