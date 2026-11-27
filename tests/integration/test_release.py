"""AppInspect on both built tarballs (drop-in and side-by-side), run once per release."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from wptest import flavor, install
from wptest.evidence import Evidence

pytestmark = pytest.mark.release

APPINSPECT = Path(sys.executable).parent / "splunk-appinspect"


@pytest.mark.parametrize("name", sorted(flavor.FLAVORS))
def test_appinspect_precert(name: str, evidence: Evidence) -> None:
    package = install.build_package(name)
    evidence.note(f"appinspect_{name}_tarball_sha256", package.sha256)
    report = evidence.folder / f"appinspect-{name}.json"
    result = subprocess.run(
        [
            str(APPINSPECT), "inspect", str(package.path),
            "--mode", "precert", "--data-format", "json", "--output-file", str(report),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=1200,
    )  # fmt: skip
    (evidence.folder / f"appinspect-{name}.log").write_text(
        result.stdout + result.stderr
    )
    assert report.exists(), (
        f"no report, exit {result.returncode}: {result.stderr[-2000:]}"
    )
    summary = cast("dict[str, int]", json.loads(report.read_text())["summary"])
    evidence.note(f"appinspect_{name}_summary", summary)
    assert summary.get("failure", 0) == 0, summary
    assert summary.get("error", 0) == 0, summary
