"""Keep the integration tests out of a run unless a command-line path names them."""

from __future__ import annotations

import sys

import pytest

INTEGRATION_PATH = "tests/integration"

collect_ignore: list[str] = (
    [] if any(INTEGRATION_PATH in arg for arg in sys.argv[1:]) else ["integration"]
)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("website-ping integration")
    group.addoption(
        "--splunk-line",
        choices=("9.4", "10.6", "all"),
        default="all",
        help="Splunk version line to test (default: all)",
    )
    group.addoption(
        "--python",
        choices=("3.9", "3.13", "all"),
        default=None,
        help="interpreter on lines that ship several (10.6): 3.9, 3.13 or all;"
        " default: the one the app selects (3.13). 9.4 always runs 3.9",
    )
    group.addoption(
        "--keep",
        action="store_true",
        help="keep the first failing stack and stop the session",
    )
    group.addoption(
        "--golden-write",
        action="store_true",
        help="golden capture: write tests/golden/<version>/ instead of comparing",
    )
