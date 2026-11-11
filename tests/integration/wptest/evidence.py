"""Per-run records and, on failure, the logs needed to investigate."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

EVIDENCE_ROOT = Path(__file__).absolute().parent.parent / ".evidence"


def secret_forms(password: str) -> list[str]:
    """The password and the base64 forms it can appear in."""
    forms = {password}
    for prefix in ("", "admin:"):
        raw = (prefix + password).encode()
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            forms.add(encode(raw).decode().rstrip("="))
    return sorted(forms, key=len, reverse=True)


def redact(text: str, password: str) -> str:
    for form in secret_forms(password):
        text = text.replace(form, "<redacted>")
    return text


class Evidence:
    """One folder per run under tests/integration/.evidence/."""

    def __init__(self, root: Path = EVIDENCE_ROOT) -> None:
        self.run = time.strftime("%Y%m%d-%H%M%S")
        self.folder = root / self.run
        self.folder.mkdir(parents=True, exist_ok=True)
        self.record: dict[str, object] = {}

    def note(self, key: str, value: object) -> None:
        """Add to the per-run record and rewrite it, so a crash keeps what is known."""
        self.record[key] = value
        (self.folder / "record.json").write_text(
            json.dumps(self.record, indent=2, sort_keys=True) + "\n"
        )

    def save(self, stack: str, name: str, text: str, password: str) -> Path:
        folder = self.folder / stack
        folder.mkdir(exist_ok=True)
        path = folder / name
        path.write_text(redact(text, password))
        return path

    def save_password(self, password: str) -> Path:
        path = self.folder / "password"
        path.touch(mode=0o600)
        path.chmod(0o600)
        path.write_text(password + "\n")
        return path
