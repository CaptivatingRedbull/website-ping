"""The side-by-side build next to Website Monitoring 2.9.7 on one instance.

Both apps have inputs named same and dated (wptest/coexist.py). same uses a
conf stanza that each app defines differently and a password stored for each
app's realm; dated has a time of day in its title. Opt-in (-m coexist), and
only on the line 2.9.7 installs on.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping
from typing import cast

import pytest
from wptest import coexist, golden, legacy, migration
from wptest.install import APP, Package
from wptest.splunk_rest import error_lines_query
from wptest.stack import Stack
from wptest.wait import wait_for

pytestmark = pytest.mark.coexist

SERVICE = "so1"
MODINPUTS = "/opt/splunk/var/lib/splunk/modinputs"
NEAR = 120.0
"""An event _time this close to _indextime is the time the input wrote."""
FAR = 3600.0
"""The dated title is twelve hours away from the check; a _time this far from
_indextime came from the title."""
EVENT_TIMEOUT = 120


def single(value: golden.FieldValue | None) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else (value[0] if value else "")


def newest(stack: Stack, scheme: str, stanza: str) -> coexist.Row:
    found = wait_for(
        f"{scheme}://{stanza} event",
        lambda: coexist.events(stack.searcher(SERVICE), scheme, stack.mark).get(
            coexist.realm(scheme, stanza)
        ),
        EVENT_TIMEOUT,
        stack.stages,
    )
    return found[-1]


def entries(stack: Stack, path: str) -> list[Mapping[str, object]]:
    return cast("list[Mapping[str, object]]", stack.rest(SERVICE).get(path)["entry"])


def acl(entry: Mapping[str, object]) -> Mapping[str, object]:
    return cast("Mapping[str, object]", entry["acl"])


def visible_from(stack: Stack, app: str, kind: str, name: str) -> dict[str, str]:
    """The apps whose object of that name a search in app sees, with their sharing."""
    query = urllib.parse.urlencode({"search": f'name="{name}"'})
    return {
        str(acl(entry)["app"]): str(acl(entry)["sharing"])
        for entry in entries(stack, f"/servicesNS/nobody/{app}/{kind}?{query}")
        if entry.get("name") == name
    }


# ---- install ------------------------------------------------------------------


def test_side_by_side_package_installed_with_its_own_scheme(
    coexist_stack: Stack,
) -> None:
    package = cast(Package, coexist_stack.facts["package"])
    assert "bin/website_ping.py" in package.files
    assert "bin/web_ping.py" not in package.files
    assert coexist_stack.rest(SERVICE).app(legacy.LEGACY_APP)
    started = [
        line
        for logged, line in coexist_stack.app_log(SERVICE)
        if logged >= coexist_stack.mark and " starting stanzas=" in line
    ]
    assert started, "no start line in website_ping.log"
    assert all(" flavor=side-by-side" in line for line in started), started


# ---- inputs, configuration, passwords -------------------------------------------


def test_each_app_runs_only_its_own_inputs(coexist_stack: Stack) -> None:
    searcher = coexist_stack.searcher(SERVICE)
    for scheme in (coexist.LEGACY_SCHEME, coexist.SCHEME):
        found = coexist.events(searcher, scheme, coexist_stack.mark)
        assert set(found) == {coexist.realm(scheme, s) for s in coexist.STANZAS}
        for stanza in coexist.STANZAS:
            urls = {
                single(row.get("url")) for row in found[coexist.realm(scheme, stanza)]
            }
            assert urls == {f"{coexist.TARGET}{coexist.path(scheme, stanza)}"}


def test_each_app_reads_its_own_conf_stanza(coexist_stack: Stack) -> None:
    old = newest(coexist_stack, coexist.LEGACY_SCHEME, coexist.SAME)
    new = newest(coexist_stack, coexist.SCHEME, coexist.SAME)
    server, port = coexist.LEGACY_PROXY
    assert (single(old.get("proxy_server")), single(old.get("proxy_port"))) == (
        server,
        port,
    )
    assert single(new.get("proxy_server")) == ""
    assert single(new.get("proxy_port")) == ""


def test_each_app_sends_its_own_password_and_user_agent(coexist_stack: Stack) -> None:
    """The input default stanza [web_ping] of 2.9.7 sets its user agent; it must not
    reach the side-by-side inputs, and each input finds the password of its realm."""
    for scheme, code in coexist.EXPECTED_CODES.items():
        event = newest(coexist_stack, scheme, coexist.SAME)
        assert single(event.get("response_code")) == code, scheme
    records = coexist_stack.target_log()
    expected_agent = {
        coexist.LEGACY_SCHEME: "Splunk Website Monitoring",
        coexist.SCHEME: "Splunk Website Ping/",
    }
    for scheme, agent in expected_agent.items():
        requests = coexist.requests_to(records, coexist.path(scheme, coexist.SAME))
        # 2.9.7 first sends a request without credentials and with the requests
        # library's own User-Agent to learn the authentication scheme (see the
        # golden basic-* cases); its user agent is on the request with credentials.
        with_credentials = [r for r in requests if r.get("authorization")]
        assert with_credentials, scheme
        checked = requests if scheme == coexist.SCHEME else with_credentials
        agents = {str(r.get("user_agent")) for r in checked}
        assert all(a.startswith(agent) for a in agents), (scheme, agents)
        sent = {str(r.get("authorization")) for r in with_credentials}
        assert sent == {"Basic"}, scheme


def test_checkpoints_in_each_scheme_folder(coexist_stack: Stack) -> None:
    for scheme in (coexist.LEGACY_SCHEME, coexist.SCHEME):
        names = coexist_stack.exec(
            SERVICE, f"ls {MODINPUTS}/{scheme} 2>/dev/null || true\n"
        ).split()
        for stanza in coexist.STANZAS:
            name = migration.checkpoint_name(coexist.realm(scheme, stanza))
            assert name in names, (scheme, stanza, names)


# ---- index time ---------------------------------------------------------------


def test_time_from_the_title_only_for_the_old_app(coexist_stack: Stack) -> None:
    """website_ping's DATETIME_CONFIG = NONE is bound to its own source; the
    events of 2.9.7 keep Splunk's timestamp extraction."""
    old = newest(coexist_stack, coexist.LEGACY_SCHEME, coexist.DATED)
    new = newest(coexist_stack, coexist.SCHEME, coexist.DATED)
    assert abs(golden.event_time(old) - golden.arrival_time(old)) > FAR, old
    assert abs(golden.event_time(new) - golden.arrival_time(new)) < NEAR, new


# ---- knowledge objects --------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        ("admin/macros", "website_monitoring_search_index"),
        ("saved/searches", "Website Performance Problem"),
        ("saved/eventtypes", "filter_website_monitoring_alerts"),
    ],
)
def test_other_apps_see_only_the_old_apps_objects(
    coexist_stack: Stack, kind: str, name: str
) -> None:
    assert visible_from(coexist_stack, "search", kind, name) == {
        legacy.LEGACY_APP: "global"
    }
    assert visible_from(coexist_stack, APP, kind, name).get(APP) == "app"


# ---- health -------------------------------------------------------------------


def test_btool_check_reports_nothing_about_website_ping(coexist_stack: Stack) -> None:
    output = coexist_stack.exec(
        SERVICE, "/opt/splunk/bin/splunk btool check 2>&1 || true\n"
    )
    problems = [line for line in output.splitlines() if APP in line]
    assert problems == []


def test_no_error_in_website_ping_log(coexist_stack: Stack) -> None:
    rows = coexist_stack.searcher(SERVICE).search(
        error_lines_query(
            f'source="*website_ping.log*" _index_earliest={int(coexist_stack.mark)}'
        )
    )
    assert rows == []
