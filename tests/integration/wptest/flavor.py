"""The build under test (--flavor) and the names that differ between the builds.

The drop-in build keeps Website Monitoring's names; the side-by-side build has its
own (docs/side-by-side.md). The config apps under apps/ are written with the
drop-in names; translate() converts their files for the side-by-side build, so
the same stanzas run against either package.
"""

from __future__ import annotations

from dataclasses import dataclass

DROP_IN_SCHEME = "web_ping"
DROP_IN_CONF = "website_monitoring"


@dataclass(frozen=True)
class Flavor:
    name: str
    scheme: str
    conf_name: str

    @property
    def conf_file(self) -> str:
        return f"{self.conf_name}.conf"

    @property
    def script(self) -> str:
        return f"bin/{self.scheme}.py"

    @property
    def checkpoint_dir(self) -> str:
        return f"/opt/splunk/var/lib/splunk/modinputs/{self.scheme}"

    def stanza(self, name: str) -> str:
        """The full stanza name, the event source and the password realm."""
        return f"{self.scheme}://{name}"

    def translate(self, relative: str, text: str) -> tuple[str, str]:
        """A config app file written with the drop-in names, for this build."""
        if self == DROP_IN:
            return relative, text
        if relative.endswith("inputs.conf"):
            text = text.replace(f"[{DROP_IN_SCHEME}://", f"[{self.scheme}://").replace(
                f"[{DROP_IN_SCHEME}]", f"[{self.scheme}]"
            )
        elif relative.endswith(f"/{DROP_IN_CONF}.conf"):
            relative = relative.removesuffix(f"{DROP_IN_CONF}.conf") + self.conf_file
        elif relative.endswith(".meta"):
            text = text.replace(f"[{DROP_IN_CONF}]", f"[{self.conf_name}]")
        return relative, text


DROP_IN = Flavor("drop-in", DROP_IN_SCHEME, DROP_IN_CONF)
SIDE_BY_SIDE = Flavor("side-by-side", "website_ping", "website_ping")
FLAVORS = {flavor.name: flavor for flavor in (DROP_IN, SIDE_BY_SIDE)}
TOPOLOGIES = {DROP_IN.name: None, SIDE_BY_SIDE.name: frozenset({"standalone"})}
"""Topologies each build runs on; None for all. The other stacks test the
migration from Website Monitoring, its golden capture or deployment, which the
side-by-side build does not change."""

_current = DROP_IN


def select(name: str) -> None:
    global _current
    _current = FLAVORS[name]


def current() -> Flavor:
    return _current
