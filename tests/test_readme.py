"""The settings reference in README.md lists exactly the keys of the spec files."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).absolute().parent.parent
README = ROOT / "README.md"
SPECS = {
    "inputs.conf": ROOT / "README" / "inputs.conf.spec",
    "website_monitoring.conf": ROOT / "README" / "website_monitoring.conf.spec",
}
SPEC_KEY = re.compile(r"^([a-z_.]+) = ", re.MULTILINE)
TABLE_KEY = re.compile(r"^\| `([a-z_.]+)` \|", re.MULTILINE)


def section(text: str, heading: str) -> str:
    """The text under a heading, up to the next heading of the same or a higher
    level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    start = lines.index(heading) + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if re.match(rf"#{{1,{level}}} ", lines[index])
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


@pytest.mark.parametrize("conf", sorted(SPECS))
def test_reference_lists_every_spec_key(conf: str) -> None:
    readme = README.read_text(encoding="utf-8")
    reference = section(section(readme, "## Settings reference"), f"### {conf}")
    documented = TABLE_KEY.findall(reference)
    spec = set(SPEC_KEY.findall(SPECS[conf].read_text(encoding="utf-8")))
    assert len(documented) == len(set(documented)), "a key is listed twice"
    assert set(documented) == spec


@pytest.mark.parametrize("document", ["README.md", "docs/migration.md"])
def test_relative_links_exist(document: str) -> None:
    path = ROOT / document
    targets = re.findall(r"\]\(([^)#:]+)\)", path.read_text(encoding="utf-8"))
    assert [target for target in targets if not (path.parent / target).exists()] == []
