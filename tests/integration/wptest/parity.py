"""The parity scenario table: one definition for the golden capture of Website
Monitoring 2.9.7 and the website-ping parity tests.

The legacy inputs.conf and website_monitoring.conf are generated from this table,
never written by hand.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlsplit

from target.server import AUTH_PASSWORD, AUTH_USER, CONTENT_CASES

from wptest.certs import SPLUNK_CERT_DIR
from wptest.stack import (
    CLOSED_TARGET_PORT,
    MTLS_PORT,
    PROXY_PASSWORD,
    PROXY_USER,
    SQUID_AUTH_PORT,
    TARGET_PORT,
)

T = f"http://target:{TARGET_PORT}"
DEFAULT_INTERVAL = "60"
SILENT_PORT = 8081
CONTENT_STRING = "Grüße"
MARKER = "WPTEST-MARKER"

Password = tuple[str, str, str]
"""(realm, username, password) of a storage/passwords entry."""


@dataclass(frozen=True)
class ParityScenario:
    """One row of the parity table. The stanza is web_ping://<title>.

    settings are the stanza's settings besides title, url and interval (which
    default to the title, the url and 60); settings may override title and interval.
    """

    title: str
    url: str
    settings: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    conf: str | None = None
    """A website_monitoring.conf stanza, set as configuration = <conf>."""
    password: Password | None = None
    min_events: int = 1
    notes: str = ""

    def stanza(self) -> dict[str, str]:
        values = {"title": self.title, "url": self.url, "interval": DEFAULT_INTERVAL}
        values.update(self.settings)
        if self.conf is not None:
            values["configuration"] = self.conf
        return values

    def matches_request(self, port: int, path: str) -> bool:
        """Whether a target log record belongs to this scenario.

        The title as one path segment (chains, redirects, auth), otherwise the
        URL's own port and path. The silent port logs an empty path.
        """
        path = path.split("?", 1)[0]
        if self.title in path.strip("/").split("/"):
            return True
        url = urlsplit(self.url)
        if port != url.port:
            return False
        return path in ("", url.path)

    def matches_proxy(self, requested: str) -> bool:
        """Whether a Squid log line's URL belongs to this scenario.

        An HTTPS request through Squid is logged as CONNECT host:port only.
        """
        if self.conf is None:
            return False
        url = urlsplit(self.url)
        if url.scheme == "https":
            return requested == f"{url.hostname}:{url.port}"
        return self.title in urlsplit(requested).path.strip("/").split("/")


def _s(**settings: str) -> Mapping[str, str]:
    return MappingProxyType(dict(settings))


AUTH = _s(username=AUTH_USER, password=AUTH_PASSWORD)
TIMEOUT_5 = _s(timeout="5")
CERTS = SPLUNK_CERT_DIR

PARITY_SCENARIOS: tuple[ParityScenario, ...] = (
    *(ParityScenario(f"status-{n}", f"{T}/status/{n}") for n in (200, 404, 503)),
    ParityScenario("title-escaping", f"{T}/done/title-escaping",
                   _s(title="He said \"hi\" it's")),
    ParityScenario("interval-units", f"{T}/done/interval-units", _s(interval="1m"),
                   min_events=2),
    ParityScenario("chain-at-3", f"{T}/chain/chain-at-3/3", _s(max_redirects="3")),
    ParityScenario("over-3", f"{T}/chain/over-3/4", _s(max_redirects="3")),
    ParityScenario("redirects-off", f"{T}/redirect/302/redirects-off",
                   _s(max_redirects="0")),
    ParityScenario("minus-one-25", f"{T}/chain/minus-one-25/25",
                   _s(max_redirects="-1")),
    ParityScenario("blank-25", f"{T}/chain/blank-25/25"),
    ParityScenario("blank-31", f"{T}/chain/blank-31/31",
                   notes="no max_redirects; requests stops at 30"),
    *(
        ParityScenario(f"redirect-{s}", f"{T}/redirect/{s}/redirect-{s}")
        for s in (301, 302, 303, 307, 308)
    ),
    ParityScenario("loop", f"{T}/loop/loop"),
    ParityScenario("refused", f"http://target:{CLOSED_TARGET_PORT}/"),
    ParityScenario("dns-failure", "http://wptest.invalid/"),
    ParityScenario("timeout", f"http://target:{SILENT_PORT}/", TIMEOUT_5),
    ParityScenario("slow-body", f"{T}/slow-body/slow-body", TIMEOUT_5),
    ParityScenario("trickled-body", f"{T}/trickle/trickled-body", TIMEOUT_5),
    *(
        ParityScenario(f"tls-{name}", f"https://target:{port}/tls-{name}")
        for port, name in (
            (8443, "valid"), (8444, "expired"), (8445, "self-signed"), (8446, "wrong-host"),
        )
    ),
    *(
        ParityScenario(f"content-{case}", f"{T}/content/{case}/content-{case}",
                       _s(should_contain_string=CONTENT_STRING))
        for case in CONTENT_CASES
    ),
    ParityScenario("match-yes", f"{T}/content/utf8-charset/match-yes",
                   _s(should_contain_string=MARKER)),
    ParityScenario("match-no", f"{T}/done/match-no", _s(should_contain_string=MARKER)),
    ParityScenario("headers", f"{T}/headers/headers", _s(return_headers="true")),
    ParityScenario("body-big", f"{T}/big/5000/body-big", _s(return_body="true"),
                   notes="body truncated to max_response_body_length (1000)"),
    ParityScenario("body-small", f"{T}/big/10/body-small", _s(return_body="1")),
    ParityScenario("thresholds", f"{T}/slow/300/thresholds",
                   _s(warning_threshold="100", error_threshold="200")),
    ParityScenario("basic-plain", f"{T}/auth/basic/basic-plain", AUTH),
    ParityScenario("basic-secure", f"{T}/auth/basic/basic-secure",
                   _s(username=AUTH_USER),
                   password=("web_ping://basic-secure", AUTH_USER, AUTH_PASSWORD)),
    ParityScenario("digest-plain", f"{T}/auth/digest/digest-plain", AUTH),
    ParityScenario("auth-wrong", f"{T}/auth/basic/auth-wrong",
                   _s(username=AUTH_USER, password="wrong")),
    ParityScenario("ntlm-offered", f"{T}/auth/ntlm/ntlm-offered", AUTH,
                   notes="NTLM not supported in website-ping (D4)"),
    ParityScenario("mtls-combined", f"https://target:{MTLS_PORT}/mtls-combined",
                   _s(client_certificate=f"{CERTS}/client-combined.pem")),
    ParityScenario("mtls-split", f"https://target:{MTLS_PORT}/mtls-split",
                   _s(client_certificate=f"{CERTS}/client.pem",
                      client_certificate_key=f"{CERTS}/client.key")),
    ParityScenario("mtls-none", f"https://target:{MTLS_PORT}/mtls-none"),
    ParityScenario("proxy-plain", f"{T}/done/proxy-plain", conf="plain"),
    ParityScenario("proxy-https", "https://target:8443/proxy-https", conf="plain"),
    ParityScenario("proxy-auth", f"{T}/done/proxy-auth", conf="auth"),
    ParityScenario("proxy-ignore", f"{T}/done/proxy-ignore", conf="ignore"),
    ParityScenario("user-agent", f"{T}/done/user-agent",
                   _s(user_agent="wptest-custom-agent")),
)  # fmt: skip

CONF_STANZAS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        # [default] as the old setup page leaves it: no proxy, the app's defaults.
        "default": _s(thread_limit="200", max_response_body_length="1000"),
        "plain": _s(proxy_server="squid", proxy_port="3128", proxy_type="http"),
        "auth": _s(
            proxy_server="squid",
            proxy_port=str(SQUID_AUTH_PORT),
            proxy_type="http",
            proxy_user=PROXY_USER,
            proxy_password=PROXY_PASSWORD,
        ),
        "ignore": _s(
            proxy_server="squid",
            proxy_port="3128",
            proxy_type="http",
            proxy_ignore="target",
        ),
    }
)

INPUTS_HEADER = (
    "# Generated from wptest/parity.py (PARITY_SCENARIOS). Do not edit by hand.\n"
)


def _stanza_text(name: str, values: Mapping[str, str]) -> str:
    for key, value in values.items():
        if "\n" in value or "\r" in value or value != value.strip():
            raise ValueError(f"[{name}] {key}: value cannot be written to a .conf file")
    return f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in values.items())


def inputs_conf(scenarios: Sequence[ParityScenario] = PARITY_SCENARIOS) -> str:
    """local/inputs.conf for the given scenarios."""
    titles = [scenario.title for scenario in scenarios]
    duplicates = sorted({title for title in titles if titles.count(title) > 1})
    if duplicates:
        raise ValueError(f"duplicate titles: {duplicates}")
    stanzas = [_stanza_text(f"web_ping://{s.title}", s.stanza()) for s in scenarios]
    return INPUTS_HEADER + "\n" + "\n".join(stanzas)


def website_monitoring_conf(
    scenarios: Sequence[ParityScenario] = PARITY_SCENARIOS,
) -> str:
    """local/website_monitoring.conf: [default] plus every stanza a scenario names."""
    names = ["default"] + sorted({s.conf for s in scenarios if s.conf is not None})
    missing = [name for name in names if name not in CONF_STANZAS]
    if missing:
        raise ValueError(f"unknown website_monitoring.conf stanzas: {missing}")
    stanzas = [_stanza_text(name, CONF_STANZAS[name]) for name in names]
    return INPUTS_HEADER + "\n" + "\n".join(stanzas)


def passwords(
    scenarios: Sequence[ParityScenario] = PARITY_SCENARIOS,
) -> list[Password]:
    return [s.password for s in scenarios if s.password is not None]


def by_title(
    scenarios: Sequence[ParityScenario] = PARITY_SCENARIOS,
) -> dict[str, ParityScenario]:
    return {scenario.title: scenario for scenario in scenarios}
