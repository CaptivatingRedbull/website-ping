"""Keep the integration tests out of a run unless a command-line path names them."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from wptest import flavor
from wptest.versions import ALL, EDGES, LINES, chosen_lines, edge_lines

INTEGRATION_PATH = "tests/integration"

collect_ignore: list[str] = (
    [] if any(INTEGRATION_PATH in arg for arg in sys.argv[1:]) else ["integration"]
)


@pytest.fixture(autouse=True)
def no_proxy_variables(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unit tests talk to loopback servers, and checks honour proxy variables: a
    proxy set on the machine running the tests must not route those requests.
    A test that needs one sets it itself. The integration tests keep them."""
    if "integration" in request.path.parts:
        return
    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("website-ping integration")
    group.addoption(
        "--splunk-line",
        default=EDGES,
        help=f"Splunk version lines to test: {', '.join(LINES)} (comma-separated),"
        f" {EDGES} ({' and '.join(edge_lines())}, default) or {ALL}",
    )
    group.addoption(
        "--python",
        choices=("3.9", "3.13", ALL),
        default=None,
        help="interpreter on lines that ship several: 3.9, 3.13 or all;"
        " default: the one the app selects. A line that ships one always runs it",
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
    group.addoption(
        "--flavor",
        choices=tuple(flavor.FLAVORS),
        default=flavor.DROP_IN.name,
        help="the package under test: drop-in (default) or side-by-side, which runs"
        " the standalone stack only",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Refuse an unknown --splunk-line before collection, as argparse choices would,
    and select the build under test."""
    try:
        _ = chosen_lines(str(config.getoption("--splunk-line")))
    except ValueError as exc:
        raise pytest.UsageError(str(exc)) from exc
    flavor.select(str(config.getoption("--flavor")))


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A self-signed certificate for 127.0.0.1 and its key, for loopback TLS servers."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    folder = tmp_path_factory.mktemp("tls")
    cert, key = folder / "cert.pem", folder / "key.pem"
    _ = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key
