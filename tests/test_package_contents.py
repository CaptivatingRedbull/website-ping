from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent

EXPECTED_FILES = {
    "README.md",
    "README/inputs.conf.spec",
    "bin/compat.py",
    "bin/logger.py",
    "bin/ping_check.py",
    "bin/ping_config.py",
    "bin/ping_events.py",
    "bin/web_ping.py",
    "default/app.conf",
    "default/data/ui/nav/default.xml",
    "default/data/ui/views/README",
    "default/inputs.conf",
    "default/props.conf",
    "metadata/default.meta",
}
EXPECTED_FOLDERS = {
    "README",
    "bin",
    "default",
    "default/data",
    "default/data/ui",
    "default/data/ui/nav",
    "default/data/ui/views",
    "metadata",
    "static",
}


def build_package() -> Path:
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "package.py")],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return Path(output.strip())


def test_package_layout_and_modes() -> None:
    with tarfile.open(build_package(), "r:gz") as tar:
        members = tar.getmembers()

    assert {member.name.split("/", 1)[0] for member in members} == {"website-ping"}
    relative = {
        member.name.split("/", 1)[1]: member for member in members if "/" in member.name
    }
    files = {name for name, member in relative.items() if member.isfile()}
    folders = {name for name, member in relative.items() if member.isdir()}
    assert files == EXPECTED_FILES
    assert folders == EXPECTED_FOLDERS
    for name in files:
        expected = 0o755 if name == "bin/web_ping.py" else 0o644
        assert relative[name].mode == expected, name
