"""Website Monitoring 2.9.7, built from its GitHub tag, for the golden capture.

Only captured on the 9.4 line: 2.9.7 is not supported on 10.x.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
import urllib.request
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

from wptest.install import install_app
from wptest.stack import INTEGRATION, Stack

LEGACY_VERSION = "2.9.7"
LEGACY_LINE = "9.4"
LEGACY_COMMIT = "442d08de5bbfed4a879de3b537eae0361de8e473"
LEGACY_URL = (
    "https://codeload.github.com/LukeMurphey/splunk-website-monitoring"
    f"/tar.gz/refs/tags/{LEGACY_VERSION}"
)
LEGACY_SHA256 = "4ec8ef6d4c6549d7cf8d8052ccc69b9749dfd6b2cb4a61c1a297a7f4725e2e55"
"""Pinned after the first download: the capture stops and prints the value to pin."""
LEGACY_APP = "website_monitoring"
CACHE = INTEGRATION / ".cache"
LEGACY_IN_CONTAINER = f"/tmp/{LEGACY_APP}-{LEGACY_VERSION}.tar.gz"
LOCAL_DIR = f"/opt/splunk/etc/apps/{LEGACY_APP}/local"
APP_CONF = "default/app.conf"


class LegacyError(RuntimeError):
    """The source archive is missing, unpinned, different or malformed."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(cache: Path = CACHE, pinned: str = LEGACY_SHA256) -> Path:
    """The tag's source archive, downloaded once into the cache, checked against the pin.

    The archive's pax header names the commit it was made from (git archive
    writes it); that is checked too, so a wrong pin cannot go unnoticed.
    """
    path = cache / f"splunk-website-monitoring-{LEGACY_VERSION}.tar.gz"
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        partial = path.with_name(path.name + ".part")
        with urllib.request.urlopen(LEGACY_URL, timeout=120) as response:
            partial.write_bytes(response.read())
        os.replace(partial, path)
    digest = sha256(path)
    with tarfile.open(path, "r:gz") as tar:
        commit = tar.pax_headers.get("comment", "")
    if commit != LEGACY_COMMIT:
        raise LegacyError(f"{path} is from commit {commit!r}, expected {LEGACY_COMMIT}")
    if not pinned:
        raise LegacyError(
            f"downloaded {path} (commit {commit}) with SHA-256 {digest}:"
            " set LEGACY_SHA256 in wptest/legacy.py to this value"
        )
    if digest != pinned:
        raise LegacyError(f"{path} has SHA-256 {digest}, pinned {pinned}")
    return path


def release_app_conf(text: str, version: str = LEGACY_VERSION) -> str:
    """default/app.conf as the 2.9.7 release has it: placeholders filled,
    the build date comment dropped."""
    lines = [
        line
        for line in text.splitlines(keepends=True)
        if not line.lstrip().startswith("# Last commit:")
    ]
    return (
        "".join(lines)
        .replace("${value.version.number}", version)
        .replace("${value.build.number}", "0")
    )


def _mode(relative: str, is_dir: bool) -> int:
    """Modes as scripts/package.py sets them: folders and bin/*.py 755, files 644."""
    path = PurePosixPath(relative)
    script = path.parent.as_posix() == "bin" and path.suffix == ".py"
    return 0o755 if is_dir or script else 0o644


def _app_path(name: str) -> str | None:
    """The member's path below src/, or None for anything outside src/.

    Raises LegacyError for an absolute path or "..": the archive is untrusted.
    """
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise LegacyError(f"unsafe member {name!r}")
    if len(path.parts) < 2 or path.parts[1] != "src":
        return None
    return PurePosixPath(*path.parts[2:]).as_posix() if len(path.parts) > 2 else ""


def _package_member(
    tar: tarfile.TarFile, member: tarfile.TarInfo
) -> tuple[tarfile.TarInfo, bytes | None] | None:
    """The package entry for one source member, or None when it is not under src/."""
    relative = _app_path(member.name)
    if relative is None:
        return None
    if not (member.isfile() or member.isdir()):
        raise LegacyError(f"{member.name} is not a file or folder")
    info = tarfile.TarInfo(LEGACY_APP + (f"/{relative}" if relative else ""))
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = member.mtime
    info.mode = _mode(relative, member.isdir())
    if member.isdir():
        info.type = tarfile.DIRTYPE
        return info, None
    extracted = tar.extractfile(member)
    if extracted is None:
        raise LegacyError(f"cannot read {member.name}")
    data = extracted.read()
    if relative == APP_CONF:
        data = release_app_conf(data.decode("utf-8")).encode("utf-8")
    info.size = len(data)
    return info, data


def build_legacy_package(source: Path, output: Path) -> Path:
    """website_monitoring-2.9.7.tar.gz from the tag archive: src/ as website_monitoring/.

    Only files and folders are taken; uid/gid 0; gzip without a name or
    timestamp, so the same source gives the same package.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    with ExitStack() as files:  # Python 3.9: no parenthesised with
        tar = files.enter_context(tarfile.open(source, "r:gz"))
        raw_out = files.enter_context(output.open("wb"))
        gz = files.enter_context(
            gzip.GzipFile(filename="", fileobj=raw_out, mode="wb", mtime=0)
        )
        out = files.enter_context(
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT)
        )
        for member in tar.getmembers():
            entry = _package_member(tar, member)
            if entry is not None:
                info, data = entry
                out.addfile(info, None if data is None else io.BytesIO(data))
    output.chmod(0o644)
    return output


def install_legacy(stack: Stack, service: str, package: Path) -> None:
    """splunk install app, like website-ping's own install."""
    stack.cp(package, service, LEGACY_IN_CONTAINER)
    install_app(stack, service, LEGACY_IN_CONTAINER)


def write_local(stack: Stack, service: str, files: dict[str, Path]) -> None:
    """Copy config files into website_monitoring/local/, owned by splunk, mode 600,
    which is where production has them."""
    stack.exec(service, f"mkdir -p {LOCAL_DIR}\n")
    for name, path in files.items():
        stack.cp(path, service, f"{LOCAL_DIR}/{name}")
    stack.exec(
        service,
        f"chown -R splunk:splunk {LOCAL_DIR}\nchmod 0600 {LOCAL_DIR}/*.conf\n",
        user="root",
    )
