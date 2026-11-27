from __future__ import annotations

import ast
import configparser
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).absolute().parent.parent

EXPECTED_FILES = {
    "LICENSE",
    "NOTICE",
    "README.md",
    "README/inputs.conf.spec",
    "README/website_monitoring.conf.spec",
    "bin/compat.py",
    "bin/logger.py",
    "bin/ping_check.py",
    "bin/ping_config.py",
    "bin/ping_events.py",
    "bin/web_ping.py",
    "bin/wp_auth.py",
    "bin/wp_content.py",
    "bin/wp_context.py",
    "bin/wp_deadline.py",
    "bin/wp_event_fields.py",
    "bin/wp_http.py",
    "bin/wp_names.py",
    "bin/wp_proxy.py",
    "bin/wp_runner.py",
    "bin/wp_splunk.py",
    "bin/wp_tls.py",
    "bin/wp_url.py",
    "bin/wp_version.py",
    "default/app.conf",
    "default/data/ui/nav/default.xml",
    "default/data/ui/views/status_overview.xml",
    "default/data/ui/views/web_ping_logs.xml",
    "default/data/ui/views/web_ping_status.xml",
    "default/data/ui/views/exec_summary.xml",
    "default/data/ui/views/site_changes.xml",
    "default/data/ui/views/status_history.xml",
    "default/eventtypes.conf",
    "default/inputs.conf",
    "default/macros.conf",
    "default/props.conf",
    "default/savedsearches.conf",
    "default/tags.conf",
    "default/transforms.conf",
    "default/website_monitoring.conf",
    "lookups/http_response_codes.csv",
    "metadata/default.meta",
    "static/appIcon.png",
    "static/appIconAlt.png",
    "static/appIconAlt_2x.png",
    "static/appIcon_2x.png",
}
EXPECTED_FOLDERS = {
    "README",
    "bin",
    "default",
    "default/data",
    "default/data/ui",
    "default/data/ui/nav",
    "default/data/ui/views",
    "lookups",
    "metadata",
    "static",
}


SIDE_BY_SIDE_RENAMES = {
    "bin/web_ping.py": "bin/website_ping.py",
    "README/website_monitoring.conf.spec": "README/website_ping.conf.spec",
    "default/website_monitoring.conf": "default/website_ping.conf",
}
EXPECTED = {
    "drop-in": (EXPECTED_FILES, "bin/web_ping.py", ""),
    "side-by-side": (
        {SIDE_BY_SIDE_RENAMES.get(name, name) for name in EXPECTED_FILES},
        "bin/website_ping.py",
        "-side-by-side",
    ),
}
"""Flavor to (files, the one executable file, package name suffix)."""


def build_package(*args: str) -> Path:
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "package.py"), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return Path(output.strip())


def app_version() -> str:
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(ROOT / "default" / "app.conf", encoding="utf-8")
    return parser.get("launcher", "version").strip()


def package_texts(path: Path) -> dict[str, str]:
    """Package file (relative to the app folder) to its text, for the text files."""
    texts: dict[str, str] = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.name.endswith(".png"):
                continue
            extracted = tar.extractfile(member)
            assert extracted is not None
            texts[member.name.split("/", 1)[1]] = extracted.read().decode("utf-8")
    return texts


@pytest.fixture(scope="module")
def drop_in() -> Path:
    return build_package()


@pytest.fixture(scope="module")
def side_by_side() -> Path:
    return build_package("--flavor", "side-by-side")


@pytest.mark.parametrize("flavor", ["drop-in", "side-by-side"])
def test_package_layout_and_modes(flavor: str) -> None:
    expected_files, executable, suffix = EXPECTED[flavor]
    package = build_package("--flavor", flavor)
    assert package.name == f"website_ping-{app_version()}{suffix}.tar.gz"
    with tarfile.open(package, "r:gz") as tar:
        members = tar.getmembers()

    assert {member.name.split("/", 1)[0] for member in members} == {"website_ping"}
    relative = {
        member.name.split("/", 1)[1]: member for member in members if "/" in member.name
    }
    files = {name for name, member in relative.items() if member.isfile()}
    folders = {name for name, member in relative.items() if member.isdir()}
    assert files == expected_files
    assert folders == EXPECTED_FOLDERS
    for name in files:
        expected = 0o755 if name == executable else 0o644
        assert relative[name].mode == expected, name
        assert relative[name].uid == relative[name].gid == 0, name
        assert relative[name].uname == relative[name].gname == "", name


def test_drop_in_ships_the_source_files_unchanged(drop_in: Path) -> None:
    for name, text in package_texts(drop_in).items():
        assert text == (ROOT / name).read_text(encoding="utf-8"), name


def test_side_by_side_changes_only_the_renamed_names(
    drop_in: Path, side_by_side: Path
) -> None:
    original = package_texts(drop_in)
    renamed = package_texts(side_by_side)
    back = {new: old for old, new in SIDE_BY_SIDE_RENAMES.items()}
    changed = {
        name for name, text in renamed.items() if original[back.get(name, name)] != text
    }
    assert changed == {
        "README.md",
        "README/inputs.conf.spec",
        "README/website_ping.conf.spec",
        "bin/wp_names.py",
        "default/app.conf",
        "default/inputs.conf",
        "default/props.conf",
        "default/website_ping.conf",
        "metadata/default.meta",
    }
    assert renamed["bin/website_ping.py"] == original["bin/web_ping.py"]


def test_side_by_side_uses_no_drop_in_name(side_by_side: Path) -> None:
    texts = package_texts(side_by_side)
    # README.md describes the drop-in names below its side-by-side note, and the
    # code's docstrings may name the Website Monitoring file they replace.
    configs = {
        name: text
        for name, text in texts.items()
        if name.startswith(("default/", "README/", "metadata/"))
    }
    for name, text in configs.items():
        assert "web_ping://" not in text, name
        assert "website_monitoring.conf" not in text, name
        assert "[web_ping]" not in text, name
        assert "export = system\n" not in text, name
    assert "[website_ping://<name>]" in texts["README/inputs.conf.spec"]
    assert "[website_ping]\n" in texts["default/inputs.conf"]
    assert "[source::website_ping://...]\n" in texts["default/props.conf"]
    assert "reload.website_ping = simple\n" in texts["default/app.conf"]
    assert "label = Website Ping (side-by-side)\n" in texts["default/app.conf"]
    assert texts["metadata/default.meta"].count("export = none\n") == 11
    assert 'CONF_NAME = "website_ping"\n' in texts["bin/wp_names.py"]
    assert 'FLAVOR = "side-by-side"\n' in texts["bin/wp_names.py"]
    assert "> **Side-by-side build.**" in texts["README.md"]
    # The proxy password keeps the realm both apps share.
    assert "website_monitoring_app_proxy" in texts["README/website_ping.conf.spec"]


def copy_app(tmp_path: Path) -> Path:
    """A copy of the scripts and the app items, to build from."""
    for name in (
        "scripts",
        "LICENSE",
        "NOTICE",
        "README.md",
        "README",
        "bin",
        "default",
        "lookups",
        "metadata",
        "static",
    ):
        source = ROOT / name
        if source.is_dir():
            _ = shutil.copytree(source, tmp_path / name)
        else:
            _ = shutil.copy2(source, tmp_path / name)
    return tmp_path


def test_side_by_side_stops_when_a_source_text_changed(tmp_path: Path) -> None:
    root = copy_app(tmp_path)
    inputs = root / "default" / "inputs.conf"
    _ = inputs.write_text(
        inputs.read_text(encoding="utf-8").replace("[web_ping]\n", "[web_ping ]\n"),
        encoding="utf-8",
    )
    run = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "package.py"),
            "--flavor",
            "side-by-side",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 1
    assert run.stderr.strip() == (
        "default/inputs.conf: '[web_ping]\\n' found 0 times, expected 1"
    )
    assert not (root / "dist").exists()


def test_missing_app_item_stops_with_clear_message(tmp_path: Path) -> None:
    script = tmp_path / "scripts" / "package.py"
    script.parent.mkdir()
    _ = script.write_text((ROOT / "scripts" / "package.py").read_text(encoding="utf-8"))
    run = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, check=False
    )
    assert run.returncode == 1
    assert run.stderr.strip() == "missing app item: LICENSE"


def string_constants(path: Path) -> list[tuple[int, str]]:
    """(line, value) of every str constant in the module that is not a docstring."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = node.body
        else:
            continue
        for index, statement in enumerate(body):
            # The module/class/function docstring, and the attribute docstrings
            # that follow an assignment.
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
                and (
                    index == 0
                    or isinstance(body[index - 1], (ast.Assign, ast.AnnAssign))
                )
            ):
                docstrings.add(id(statement.value))
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_code_takes_the_conf_name_from_wp_names() -> None:
    """The side-by-side build renames the conf file by rewriting bin/wp_names.py only,
    so no other module may spell the name out in a string the code uses."""
    stray = [
        f"{path.name}:{line}"
        for path in sorted((ROOT / "bin").glob("*.py"))
        if path.name != "wp_names.py"
        for line, value in string_constants(path)
        if re.search(r"website_monitoring(?!_app_proxy)", value)
    ]
    assert stray == []
