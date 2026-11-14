"""The Splunk versions and interpreters under test. Bumping a patch release changes one entry."""

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
    pythons: tuple[str, ...]
    """Interpreters the line ships. The first is the one the app's own
    python.required selects; the others need an override in the config app."""

    @property
    def pinned_image(self) -> str:
        return f"{self.image}@{self.digest}"


LINES: dict[str, SplunkLine] = {
    "9.4": SplunkLine(
        image="splunk/splunk:9.4.17",
        digest="sha256:8d3849f78c2814fd65e68a69aeaa4d1dc79f37e661dbe48e791f4552b025def5",
        licence_env=_LICENCE_ENV,
        pythons=("3.9",),
    ),
    "10.6": SplunkLine(
        image="splunk/splunk:10.6.1.1",
        digest="sha256:2a7cf9d2e8a2226773a9fac95b5e0e2cc8752496abfb134a21bdf8f67c9ee44d",
        licence_env=_LICENCE_ENV,
        pythons=("3.13", "3.9"),
    ),
}


@dataclass(frozen=True)
class Runtime:
    """A Splunk line and the interpreter the input runs on there."""

    line: str
    python: str

    @property
    def id(self) -> str:
        return f"{self.line}-py{self.python}"

    @property
    def interpreter(self) -> str:
        """Base name of the executable Splunk starts, as in /opt/splunk/bin."""
        return f"python{self.python}"

    @property
    def overridden(self) -> bool:
        """True when the config app must set python.required to get this interpreter."""
        return self.python != LINES[self.line].pythons[0]


ALL_RUNTIMES: tuple[Runtime, ...] = tuple(
    Runtime(line, python) for line, spec in LINES.items() for python in spec.pythons
)


def select_runtimes(line_choice: str, python_choice: str | None) -> list[Runtime]:
    """The runtimes for --splunk-line and --python, in ALL_RUNTIMES order.

    A line that ships one interpreter always runs it. On a line with several,
    no choice means the one the app selects itself, "all" means every one, and a
    version means that one; a version the line does not ship is an error.
    """
    selected: list[Runtime] = []
    for line, spec in LINES.items():
        if line_choice not in ("all", line):
            continue
        if len(spec.pythons) == 1 or python_choice is None:
            pythons = spec.pythons[:1]
        elif python_choice == "all":
            pythons = spec.pythons
        elif python_choice in spec.pythons:
            pythons = (python_choice,)
        else:
            raise ValueError(f"Splunk {line} does not ship Python {python_choice}")
        selected += [Runtime(line, python) for python in pythons]
    return selected
