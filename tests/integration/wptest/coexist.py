"""Website Monitoring 2.9.7 and the side-by-side build of website-ping on one instance.

Both apps get inputs with the same stanza names, their own conf stanza of the
same name with different proxy settings, and their own stored password. The
tests check that neither app sees the other's inputs, defaults, configuration,
passwords, checkpoints or index-time settings, and that the knowledge objects
users' searches call keep resolving to Website Monitoring.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from target.server import AUTH_PASSWORD, AUTH_USER

from wptest import golden
from wptest.splunk_rest import Searcher

TARGET = "http://target:8080"
LEGACY_SCHEME = "web_ping"
SCHEME = "website_ping"
"""The side-by-side build's scheme."""
SHARED_CONFIGURATION = "shared"
"""A stanza both apps define in their own conf file, with different proxies."""
LEGACY_PROXY = ("squid", "3128")
USERNAME = AUTH_USER
PASSWORDS = {LEGACY_SCHEME: "wptest-wrong-password", SCHEME: AUTH_PASSWORD}
"""Stored for each app's input of the same name, under each scheme's realm. The
target accepts only AUTH_PASSWORD and logs no credentials, so the response code
tells which password an input sent: an app that read the other's realm would get
the other code."""
EXPECTED_CODES = {LEGACY_SCHEME: "401", SCHEME: "200"}
INTERVAL = 15
SAME = "same"
"""The stanza name both apps use for an authenticated input."""
DATED = "dated"
"""The stanza name both apps use for an input whose title holds a time of day."""
STANZAS = (SAME, DATED)
QUERY = (
    'search index=main sourcetype=web_ping source="{scheme}://*"'
    " _index_earliest={since}"
    " | eval wptest_time=_time, wptest_indextime=_indextime"
    " | table wptest_time wptest_indextime source title url response_code"
    " proxy_server proxy_port"
)


@dataclass(frozen=True)
class Config:
    """The inputs of both apps; the dated title is fixed when the setup writes it."""

    dated_title: str


def far_time_of_day(now: float | None = None) -> str:
    """A UTC time of day twelve hours from now, so a _time taken from it is far
    from the time the event arrives, whatever the hour of the run."""
    moment = time.gmtime((time.time() if now is None else now) + 12 * 3600)
    return time.strftime("%H:%M:%S", moment)


def path(scheme: str, stanza: str) -> str:
    """The target path each app's input requests, so the target log tells them apart."""
    if stanza == SAME:
        return f"/auth/basic/{scheme}-{stanza}"
    return f"/done/{scheme}-{stanza}"


def urls() -> list[str]:
    """Every URL of the scenario, for the preflight's stanza URL check."""
    return [
        f"{TARGET}{path(scheme, stanza)}"
        for scheme in (LEGACY_SCHEME, SCHEME)
        for stanza in STANZAS
    ]


def inputs_conf(scheme: str, config: Config) -> str:
    return (
        f"[{scheme}://{SAME}]\n"
        f"title = {SAME}\n"
        f"url = {TARGET}{path(scheme, SAME)}\n"
        f"interval = {INTERVAL}\n"
        f"configuration = {SHARED_CONFIGURATION}\n"
        f"username = {USERNAME}\n"
        "\n"
        f"[{scheme}://{DATED}]\n"
        f"title = {config.dated_title} check\n"
        f"url = {TARGET}{path(scheme, DATED)}\n"
        f"interval = {INTERVAL}\n"
    )


def legacy_conf() -> str:
    """website_monitoring.conf in website_monitoring/local: requests through Squid."""
    server, port = LEGACY_PROXY
    return f"[{SHARED_CONFIGURATION}]\nproxy_server = {server}\nproxy_port = {port}\n"


def side_by_side_conf() -> str:
    """website_ping.conf in the config app: no proxy, environment proxies ignored."""
    return f"[{SHARED_CONFIGURATION}]\nproxy_ignore = *\n"


def realm(scheme: str, stanza: str = SAME) -> str:
    return f"{scheme}://{stanza}"


Row = dict[str, golden.FieldValue]


def events(searcher: Searcher, scheme: str, since: float) -> dict[str, list[Row]]:
    """Check events of one scheme indexed since since, by source, oldest first."""
    _ = searcher.search(QUERY.format(scheme=scheme, since=int(since)))
    by_source: dict[str, list[Row]] = {}
    for row in golden.parse_export(searcher.last_result):
        by_source.setdefault(str(row.get("source")), []).append(row)
    return {
        source: sorted(rows, key=golden.arrival_order)
        for source, rows in by_source.items()
    }


def all_events(
    searcher: Searcher, since: float
) -> dict[str, dict[str, list[Row]]] | None:
    """Events of both schemes once every stanza of both has one, else None."""
    found = {
        scheme: events(searcher, scheme, since) for scheme in (LEGACY_SCHEME, SCHEME)
    }
    complete = all(
        realm(scheme, stanza) in found[scheme] for scheme in found for stanza in STANZAS
    )
    return found if complete else None


def requests_to(
    records: Sequence[Mapping[str, object]], target_path: str
) -> list[Mapping[str, object]]:
    return [record for record in records if record.get("path") == target_path]
