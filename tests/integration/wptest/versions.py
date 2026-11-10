"""The Splunk versions under test. Bumping a patch release changes one entry."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

_LICENCE_ENV: Mapping[str, str] = {
    "SPLUNK_START_ARGS": "--accept-license",
    "SPLUNK_GENERAL_TERMS": "--accept-sgt-current-at-splunk-com",
}


@dataclass(frozen=True)
class SplunkLine:
    image: str
    digest: str
    licence_env: Mapping[str, str]
    interpreter: str

    @property
    def pinned_image(self) -> str:
        return f"{self.image}@{self.digest}"


LINES: dict[str, SplunkLine] = {
    "9.4": SplunkLine(
        image="splunk/splunk:9.4.17",
        digest="sha256:8d3849f78c2814fd65e68a69aeaa4d1dc79f37e661dbe48e791f4552b025def5",
        licence_env=_LICENCE_ENV,
        interpreter="python3.9",
    ),
    "10.6": SplunkLine(
        image="splunk/splunk:10.6.1.1",
        digest="sha256:2a7cf9d2e8a2226773a9fac95b5e0e2cc8752496abfb134a21bdf8f67c9ee44d",
        licence_env=_LICENCE_ENV,
        interpreter="python3.13",
    ),
}
