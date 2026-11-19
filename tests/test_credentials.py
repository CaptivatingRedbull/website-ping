"""The credential scan helpers of the integration tests (wptest/credentials.py)."""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path

import pytest
from wptest.credentials import (
    credential_forms,
    find_credentials,
    grep_script,
    parse_grep,
)

USER, PASSWORD = "wpuser", "p@ss word/+%"


def test_forms_cover_plain_encoded_and_basic() -> None:
    forms = credential_forms(USER, PASSWORD)
    assert PASSWORD in forms
    assert "p%40ss%20word%2F%2B%25" in forms
    token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    assert token.rstrip("=") in forms
    urlsafe = base64.urlsafe_b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    assert urlsafe.rstrip("=") in forms
    assert forms == sorted(forms, key=len, reverse=True)


def test_short_passwords_are_refused() -> None:
    with pytest.raises(ValueError, match="too short"):
        _ = credential_forms("u", "pw")


def test_find_reports_labels_not_secrets() -> None:
    secrets = {"input": credential_forms(USER, PASSWORD)}
    token = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    texts = {
        "clean": "nothing here",
        "log": f"Authorization: Basic {token}",
        "url": "http://proxy:p%40ss%20word%2F%2B%25@squid:3128",
    }
    assert find_credentials(texts, secrets) == [("log", "input"), ("url", "input")]


def test_grep_script_finds_files_with_any_form(tmp_path: Path) -> None:
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.log").write_text(f"pw={PASSWORD}\n")
    (tmp_path / "logs" / "b.log").write_text("clean\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "inputs.conf").write_text(
        "x = " + credential_forms(USER, PASSWORD)[-1] + "\n"
    )
    secrets = {
        "web_ping://basic-plain wpuser": credential_forms(USER, PASSWORD),
        "other": credential_forms(USER, "not-present-anywhere"),
    }
    script = grep_script(
        secrets, [str(tmp_path / "logs"), str(tmp_path / "ap*"), "/nonexistent"]
    )
    output = subprocess.run(
        ["bash", "-s"], input=script, capture_output=True, text=True, check=True
    ).stdout
    assert sorted(parse_grep(output)) == [
        (str(tmp_path / "app" / "inputs.conf"), "web_ping://basic-plain wpuser"),
        (str(tmp_path / "logs" / "a.log"), "web_ping://basic-plain wpuser"),
    ]


def test_grep_script_refuses_unsafe_labels() -> None:
    with pytest.raises(ValueError, match="label"):
        _ = grep_script({"a'b": ["longenough"]}, ["/tmp"])
