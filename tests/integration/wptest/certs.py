"""A test certificate authority, the target's server certificates and a client certificate."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

SERVER_EXTENSIONS = """\
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:{host}
"""
CLIENT_EXTENSIONS = """\
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""
CLIENT_CN = "wptest-client"
SPLUNK_CERT_DIR = "/opt/wptest/certs"
"""Where the Splunk containers get ca.pem and the client certificate files."""


@dataclass(frozen=True)
class Certificates:
    folder: Path
    """Holds ca.pem, <name>.pem and <name>.key for each server certificate, and the
    client certificate as client.pem + client.key and as client-combined.pem."""

    @property
    def ca(self) -> Path:
        return self.folder / "ca.pem"

    @property
    def server_files(self) -> list[Path]:
        names = ("valid", "expired", "self-signed", "wrong-host")
        return [
            self.folder / f"{name}.{kind}" for name in names for kind in ("pem", "key")
        ]

    @property
    def splunk_files(self) -> list[Path]:
        """Copied to SPLUNK_CERT_DIR in each Splunk container."""
        names = ("ca.pem", "client.pem", "client.key", "client-combined.pem")
        return [self.folder / name for name in names]


def _openssl(folder: Path, *args: str) -> None:
    subprocess.run(["openssl", *args], cwd=folder, check=True, capture_output=True)


SERIALS = {"valid": "1001", "expired": "1002", "wrong-host": "1003", "client": "1004"}


def _signed(
    folder: Path, name: str, common_name: str, extensions: str, *validity: str
) -> None:
    _openssl(
        folder,
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={common_name}",
    )  # fmt: skip
    extension_file = folder / f"{name}.ext"
    extension_file.write_text(extensions)
    _openssl(
        folder,
        "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-set_serial", SERIALS[name], "-extfile", extension_file.name,
        "-out", f"{name}.pem", *validity,
    )  # fmt: skip


def _server(folder: Path, name: str, host: str, *validity: str) -> None:
    _signed(folder, name, host, SERVER_EXTENSIONS.format(host=host), *validity)


def generate(folder: Path) -> Certificates:
    folder.mkdir(parents=True, exist_ok=True)
    _openssl(
        folder,
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=website-ping test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )  # fmt: skip
    _server(folder, "valid", "target", "-days", "2")
    _server(
        folder, "expired", "target",
        "-not_before", "20200101000000Z", "-not_after", "20200201000000Z",
    )  # fmt: skip
    _server(folder, "wrong-host", "wrong.invalid", "-days", "2")
    _openssl(
        folder,
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", "self-signed.key", "-out", "self-signed.pem", "-subj", "/CN=target",
        "-addext", "subjectAltName=DNS:target",
        "-addext", "basicConstraints=critical,CA:FALSE",
    )  # fmt: skip
    _signed(folder, "client", CLIENT_CN, CLIENT_EXTENSIONS, "-days", "2")
    combined = folder / "client-combined.pem"
    combined.write_text(
        (folder / "client.pem").read_text() + (folder / "client.key").read_text()
    )
    (folder / "ca.pem").chmod(0o644)
    return Certificates(folder)
