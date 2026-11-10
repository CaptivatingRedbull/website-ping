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
        "--keep",
        action="store_true",
        help="keep the first failing stack and stop the session",
    )
