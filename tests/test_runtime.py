from __future__ import annotations

import re
import tarfile
from pathlib import Path

import pytest
from wptest.install import build_config_app, python_override
from wptest.versions import (
    ALL_RUNTIMES,
    LINES,
    Runtime,
    SplunkLine,
    chosen_lines,
    edge_lines,
    select_runtimes,
    version_key,
)

APP_PYTHONS = ("3.9", "3.13")
"""The interpreters of python.required in the app's default/inputs.conf."""


def _line(*pythons: str) -> SplunkLine:
    return SplunkLine(
        image="splunk/splunk:0.0.0", digest="sha256:0", licence_env={}, pythons=pythons
    )


TABLE = {
    "9.4": _line("3.9"),
    "10.0": _line("3.9"),
    "10.2": _line("3.13", "3.9"),
    "10.6": _line("3.13", "3.9"),
}
"""A line table independent of the lines under test, for the selection rules."""


def _ids(runtimes: list[Runtime]) -> list[str]:
    return [r.id for r in runtimes]


@pytest.mark.parametrize(
    ("line", "python", "expected"),
    [
        ("edges", None, ["9.4-py3.9", "10.6-py3.13"]),
        ("edges", "all", ["9.4-py3.9", "10.6-py3.13", "10.6-py3.9"]),
        ("all", None, ["9.4-py3.9", "10.0-py3.9", "10.2-py3.13", "10.6-py3.13"]),
        (
            "all",
            "all",
            [
                "9.4-py3.9",
                "10.0-py3.9",
                "10.2-py3.13",
                "10.2-py3.9",
                "10.6-py3.13",
                "10.6-py3.9",
            ],
        ),
        ("all", "3.9", ["9.4-py3.9", "10.0-py3.9", "10.2-py3.9", "10.6-py3.9"]),
        ("all", "3.13", ["9.4-py3.9", "10.0-py3.9", "10.2-py3.13", "10.6-py3.13"]),
        ("10.6", "3.9", ["10.6-py3.9"]),
        ("10.2", "all", ["10.2-py3.13", "10.2-py3.9"]),
        ("10.0", "3.13", ["10.0-py3.9"]),
        ("9.4", None, ["9.4-py3.9"]),
        ("10.2,10.0", None, ["10.0-py3.9", "10.2-py3.13"]),
        ("10.6, edges", None, ["9.4-py3.9", "10.6-py3.13"]),
    ],
)
def test_select_runtimes(line: str, python: str | None, expected: list[str]) -> None:
    assert _ids(select_runtimes(line, python, TABLE)) == expected


def test_unknown_line_is_an_error() -> None:
    with pytest.raises(ValueError, match=r"unknown Splunk line '9\.3'"):
        _ = chosen_lines("9.3", TABLE)


def test_unknown_interpreter_on_a_line_with_several_is_an_error() -> None:
    with pytest.raises(ValueError, match="does not ship Python 3.7"):
        _ = select_runtimes("10.6", "3.7", TABLE)


def test_edges_of_a_single_line_table() -> None:
    assert edge_lines({"9.4": _line("3.9")}) == ("9.4",)


def test_lines_are_oldest_first() -> None:
    assert list(LINES) == sorted(LINES, key=version_key)


@pytest.mark.parametrize("line", list(LINES))
def test_line_entry(line: str) -> None:
    """Each pinned image belongs to its line, and the first interpreter is the one
    the app's inputs.conf selects: the highest of 3.9 and 3.13 the line ships."""
    spec = LINES[line]
    assert spec.image.startswith(f"splunk/splunk:{line}."), spec.image
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", spec.digest), spec.digest
    assert spec.pythons, line
    assert set(spec.pythons) <= set(APP_PYTHONS), spec.pythons
    assert len(set(spec.pythons)) == len(spec.pythons), spec.pythons
    assert spec.pythons[0] == max(spec.pythons, key=version_key), spec.pythons


def test_default_selection_is_the_edge_lines_on_their_own_interpreter() -> None:
    assert select_runtimes("edges", None) == [
        Runtime(line, LINES[line].pythons[0]) for line in edge_lines()
    ]


def test_all_runtimes_covers_every_interpreter_of_every_line() -> None:
    assert list(ALL_RUNTIMES) == select_runtimes("all", "all")


def test_only_the_non_default_interpreters_are_overridden() -> None:
    for runtime in ALL_RUNTIMES:
        assert runtime.overridden == (runtime.python != LINES[runtime.line].pythons[0])
        assert runtime.interpreter == f"python{runtime.python}"
        assert runtime.id == f"{runtime.line}-py{runtime.python}"


def _overridden() -> Runtime:
    runtime = next((r for r in ALL_RUNTIMES if r.overridden), None)
    if runtime is None:
        pytest.skip("no line under test ships a second interpreter")
    return runtime


def test_override_goes_into_local_of_the_config_app(tmp_path: Path) -> None:
    runtime = _overridden()
    source = tmp_path / "app"
    (source / "default").mkdir(parents=True)
    _ = (source / "default" / "inputs.conf").write_text("[web_ping://a]\n")
    archive = build_config_app(
        source, tmp_path / "app.tar.gz", extra=python_override(runtime)
    )
    with tarfile.open(archive) as tar:
        members = {m.name: m for m in tar.getmembers()}
        local = tar.extractfile(members["website_ping_inputs/local/inputs.conf"])
        assert local is not None
        assert local.read() == (
            f"[web_ping]\npython.required = {runtime.python}\n".encode()
        )
    assert members["website_ping_inputs/local"].isdir()
    assert members["website_ping_inputs/local"].mode == 0o755
    assert members["website_ping_inputs/local/inputs.conf"].mode == 0o644
    assert "website_ping_inputs/default/inputs.conf" in members


def test_default_runtimes_need_no_override() -> None:
    for runtime in ALL_RUNTIMES:
        if not runtime.overridden:
            assert python_override(runtime) == {}


def test_extra_must_not_replace_a_source_file(tmp_path: Path) -> None:
    runtime = _overridden()
    source = tmp_path / "app"
    (source / "local").mkdir(parents=True)
    _ = (source / "local" / "inputs.conf").write_text("")
    with pytest.raises(ValueError, match="already in"):
        _ = build_config_app(
            source, tmp_path / "app.tar.gz", extra=python_override(runtime)
        )
