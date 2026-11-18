"""Keep the integration tests out of a run unless a command-line path names them."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

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
