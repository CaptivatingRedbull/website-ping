"""Find passwords in captured text, in every form a check could leak them: as
written, percent-encoded (proxy URL) and inside a Basic token."""

from __future__ import annotations

import base64
import re
import shlex
from collections.abc import Mapping, Sequence
from urllib.parse import quote

MIN_FORM_LENGTH = 8
"""Shorter forms would match by chance; the test passwords are all longer."""

_LABEL = re.compile(r"[A-Za-z0-9 _.:/-]+")
"""Labels go into the grep script's sed command unquoted."""


def credential_forms(username: str, password: str) -> list[str]:
    """The password as written and percent-encoded, and user:password in base64
    (standard and URL-safe, without padding, which a log line may cut)."""
    forms = {password, quote(password, safe="")}
    raw = f"{username}:{password}".encode()
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        forms.add(encode(raw).decode().rstrip("="))
    short = sorted(form for form in forms if len(form) < MIN_FORM_LENGTH)
    if short:
        raise ValueError(f"password forms too short to search for: {len(short)}")
    return sorted(forms, key=len, reverse=True)


def find_credentials(
    texts: Mapping[str, str], secrets: Mapping[str, Sequence[str]]
) -> list[tuple[str, str]]:
    """(source, label) for every source that contains a form of a secret. The
    labels name the secrets, so a report never repeats one."""
    return [
        (source, label)
        for source, text in texts.items()
        for label, forms in secrets.items()
        if any(form in text for form in forms)
    ]


def grep_script(secrets: Mapping[str, Sequence[str]], paths: Sequence[str]) -> str:
    """A bash script that prints "<label>\t<file>" for every file under paths that
    contains a form of a secret. Given on standard input, so the forms never show
    in a process list; paths may hold globs."""
    lines = ["shopt -s nullglob"]
    targets = " ".join(paths)
    for label, forms in secrets.items():
        if not _LABEL.fullmatch(label):
            raise ValueError(f"label not usable in the script: {label!r}")
        patterns = " ".join(f"-e {shlex.quote(form)}" for form in forms)
        lines.append(
            f"grep -rlF {patterns} -- {targets} 2>/dev/null | sed 's|^|{label}\\t|' || true"
        )
    return "\n".join(lines) + "\n"


def parse_grep(output: str) -> list[tuple[str, str]]:
    """(file, label) pairs from the output of grep_script."""
    found: list[tuple[str, str]] = []
    for line in output.splitlines():
        label, sep, path = line.partition("\t")
        if sep:
            found.append((path, label))
    return found
