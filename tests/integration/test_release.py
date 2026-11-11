"""AppInspect on the built tarball, run once per release."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from wptest.evidence import Evidence
from wptest.install import Package

pytestmark = pytest.mark.release

APPINSPECT = Path(sys.executable).parent / "splunk-appinspect"


def test_appinspect_precert(package: Package, evidence: Evidence) -> None:
    report = evidence.folder / "appinspect.json"
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
    (evidence.folder / "appinspect.log").write_text(result.stdout + result.stderr)
    assert report.exists(), (
        f"no report, exit {result.returncode}: {result.stderr[-2000:]}"
    )
    summary = cast("dict[str, int]", json.loads(report.read_text())["summary"])
    evidence.note("appinspect_summary", summary)
    assert summary.get("failure", 0) == 0, summary
    assert summary.get("error", 0) == 0, summary
