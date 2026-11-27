"""The integration harness converts its config apps for the side-by-side build."""

from __future__ import annotations

import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from wptest import flavor, install
from wptest.versions import ALL_RUNTIMES

STANDALONE = install.APPS_DIR / "standalone"


@pytest.fixture
def side_by_side() -> Iterator[flavor.Flavor]:
    flavor.select(flavor.SIDE_BY_SIDE.name)
    try:
        yield flavor.current()
    finally:
        flavor.select(flavor.DROP_IN.name)


def archive_texts(path: Path) -> dict[str, str]:
    texts: dict[str, str] = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile():
                extracted = tar.extractfile(member)
                assert extracted is not None
                texts[member.name.split("/", 1)[1]] = extracted.read().decode()
    return texts


def test_drop_in_keeps_the_files() -> None:
    text = "[web_ping://x]\nurl = http://target:8080/\n"
    assert flavor.DROP_IN.translate("default/inputs.conf", text) == (
        "default/inputs.conf",
        text,
    )


def test_names_of_each_flavor() -> None:
    assert flavor.SIDE_BY_SIDE.stanza("x") == "website_ping://x"
    assert flavor.SIDE_BY_SIDE.conf_file == "website_ping.conf"
    assert flavor.SIDE_BY_SIDE.script == "bin/website_ping.py"
    assert flavor.SIDE_BY_SIDE.checkpoint_dir.endswith("/modinputs/website_ping")
    assert flavor.DROP_IN.stanza("x") == "web_ping://x"
    assert flavor.DROP_IN.checkpoint_dir.endswith("/modinputs/web_ping")


def test_config_app_for_the_side_by_side_build(
    side_by_side: flavor.Flavor, tmp_path: Path
) -> None:
    archive = install.build_config_app(
        STANDALONE,
        tmp_path / "config.tar.gz",
        extra={"local/inputs.conf": "[web_ping]\npython.required = 3.9\n"},
    )
    texts = archive_texts(archive)
    assert "default/website_monitoring.conf" not in texts
    assert texts["default/website_ping.conf"] == (
        STANDALONE / "default" / "website_monitoring.conf"
    ).read_text(encoding="utf-8")
    inputs = texts["default/inputs.conf"]
    assert "[web_ping://" not in inputs
    assert inputs.count("[website_ping://") == (
        (STANDALONE / "default" / "inputs.conf").read_text().count("[web_ping://")
    )
    assert texts["local/inputs.conf"] == "[website_ping]\npython.required = 3.9\n"
    meta = texts["metadata/default.meta"]
    assert "[website_ping]\nexport = system" in meta
    assert "[website_monitoring]" not in meta
    assert texts["default/app.conf"] == (STANDALONE / "default" / "app.conf").read_text(
        encoding="utf-8"
    )


def test_python_override_names_the_scheme(side_by_side: flavor.Flavor) -> None:
    runtime = next(r for r in ALL_RUNTIMES if r.overridden)
    assert install.python_override(runtime) == {
        "local/inputs.conf": f"[website_ping]\npython.required = {runtime.python}\n"
    }
