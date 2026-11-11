"""A test certificate authority and the target's four server certificates."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

LEAF_EXTENSIONS = """\
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:{host}
"""


@dataclass(frozen=True)
class Certificates:
    folder: Path
    """Holds ca.pem and <name>.pem and <name>.key for each server certificate."""

    @property
    def ca(self) -> Path:
        return self.folder / "ca.pem"

    @property
    def server_files(self) -> list[Path]:
        names = ("valid", "expired", "self-signed", "wrong-host")
        return [
            self.folder / f"{name}.{kind}" for name in names for kind in ("pem", "key")
        ]


def _openssl(folder: Path, *args: str) -> None:
    subprocess.run(["openssl", *args], cwd=folder, check=True, capture_output=True)


SERIALS = {"valid": "1001", "expired": "1002", "wrong-host": "1003"}


def _signed(folder: Path, name: str, host: str, *validity: str) -> None:
    _openssl(
        folder,
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={host}",
    )  # fmt: skip
    extensions = folder / f"{name}.ext"
    extensions.write_text(LEAF_EXTENSIONS.format(host=host))
    _openssl(
        folder,
        "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-set_serial", SERIALS[name], "-extfile", extensions.name,
        "-out", f"{name}.pem", *validity,
    )  # fmt: skip


def generate(folder: Path) -> Certificates:
    folder.mkdir(parents=True, exist_ok=True)
    _openssl(
        folder,
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=website-ping test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )  # fmt: skip
    _signed(folder, "valid", "target", "-days", "2")
    _signed(
        folder, "expired", "target",
        "-not_before", "20200101000000Z", "-not_after", "20200201000000Z",
    )  # fmt: skip
    _signed(folder, "wrong-host", "wrong.invalid", "-days", "2")
    _openssl(
        folder,
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", "self-signed.key", "-out", "self-signed.pem", "-subj", "/CN=target",
        "-addext", "subjectAltName=DNS:target",
        "-addext", "basicConstraints=critical,CA:FALSE",
    )  # fmt: skip
    (folder / "ca.pem").chmod(0o644)
    return Certificates(folder)
