from __future__ import annotations

import tarfile
from pathlib import Path

import pytest
from wptest.install import build_config_app, python_override
from wptest.versions import ALL_RUNTIMES, Runtime, select_runtimes

R94 = Runtime("9.4", "3.9")
R106 = Runtime("10.6", "3.13")
R106_39 = Runtime("10.6", "3.9")


@pytest.mark.parametrize(
    ("line", "python", "expected"),
    [
        ("all", None, [R94, R106]),
        ("all", "all", [R94, R106, R106_39]),
        ("all", "3.9", [R94, R106_39]),
        ("all", "3.13", [R94, R106]),
        ("10.6", "3.9", [R106_39]),
        ("10.6", "all", [R106, R106_39]),
        ("9.4", "3.13", [R94]),
        ("9.4", None, [R94]),
    ],
)
def test_select_runtimes(
    line: str, python: str | None, expected: list[Runtime]
) -> None:
    assert select_runtimes(line, python) == expected


def test_unknown_interpreter_on_a_line_with_several_is_an_error() -> None:
    with pytest.raises(ValueError, match="does not ship Python 3.7"):
        select_runtimes("10.6", "3.7")


def test_only_the_non_default_interpreter_is_overridden() -> None:
    assert [r for r in ALL_RUNTIMES if r.overridden] == [R106_39]
    assert R106_39.id == "10.6-py3.9"
    assert R106_39.interpreter == "python3.9"


def test_override_goes_into_local_of_the_config_app(tmp_path: Path) -> None:
    source = tmp_path / "app"
    (source / "default").mkdir(parents=True)
    _ = (source / "default" / "inputs.conf").write_text("[web_ping://a]\n")
    archive = build_config_app(
        source, tmp_path / "app.tar.gz", extra=python_override(R106_39)
    )
    with tarfile.open(archive) as tar:
        members = {m.name: m for m in tar.getmembers()}
        local = tar.extractfile(members["website_ping_inputs/local/inputs.conf"])
        assert local is not None
        assert local.read() == b"[web_ping]\npython.required = 3.9\n"
    assert members["website_ping_inputs/local"].isdir()
    assert members["website_ping_inputs/local"].mode == 0o755
    assert members["website_ping_inputs/local/inputs.conf"].mode == 0o644
    assert "website_ping_inputs/default/inputs.conf" in members


def test_default_runtimes_need_no_override() -> None:
    assert python_override(R94) == {}
    assert python_override(R106) == {}


def test_extra_must_not_replace_a_source_file(tmp_path: Path) -> None:
    source = tmp_path / "app"
    (source / "local").mkdir(parents=True)
    _ = (source / "local" / "inputs.conf").write_text("")
    with pytest.raises(ValueError, match="already in"):
        _ = build_config_app(
            source, tmp_path / "app.tar.gz", extra=python_override(R106_39)
        )
