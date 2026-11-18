"""The parity scenario table and the legacy config generated from it (wptest/parity.py)."""

from __future__ import annotations

import configparser
from urllib.parse import urlsplit

import pytest
from ping_config import ConfigError, build_settings
from target import server
from wptest import parity
from wptest.parity import PARITY_SCENARIOS, ParityScenario
from wptest.preflight import ALLOWED_STANZA_HOSTS
from wptest.stack import PROXY_PASSWORD, PROXY_USER


def parse(text: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(
        interpolation=None, strict=True, delimiters=("=",)
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(text)
    return parser


def test_titles_are_unique_and_safe() -> None:
    titles = [s.title for s in PARITY_SCENARIOS]
    assert len(titles) == len(set(titles))
    for title in titles:
        assert title.replace("-", "").isalnum(), title


def test_inputs_conf_matches_the_table() -> None:
    parser = parse(parity.inputs_conf())
    assert parser.sections() == [f"web_ping://{s.title}" for s in PARITY_SCENARIOS]
    for scenario in PARITY_SCENARIOS:
        assert dict(parser[f"web_ping://{scenario.title}"]) == scenario.stanza()


def test_stanza_defaults_and_overrides() -> None:
    plain = ParityScenario("a", "http://target:8080/done/a")
    assert plain.stanza() == {
        "title": "a",
        "url": "http://target:8080/done/a",
        "interval": "60",
    }
    escaped = parity.by_title()["title-escaping"].stanza()
    assert escaped["title"] == 'He said "hi" it\'s'
    assert parity.by_title()["interval-units"].stanza()["interval"] == "1m"
    assert parity.by_title()["proxy-auth"].stanza()["configuration"] == "auth"


def test_values_with_line_breaks_are_refused() -> None:
    bad = ParityScenario(
        "bad", "http://target:8080/", parity.MappingProxyType({"title": "a\nb"})
    )
    with pytest.raises(ValueError):
        parity.inputs_conf([bad])


def test_website_monitoring_conf_has_default_and_named_stanzas() -> None:
    parser = parse(parity.website_monitoring_conf())
    # configparser hides [default]-named sections only for "DEFAULT"; check by name.
    assert parser.sections() == ["default", "auth", "ignore", "plain"]
    assert "proxy_server" not in parser["default"]
    assert parser["ignore"]["proxy_ignore"] == "target"


def test_website_ping_conf_stores_the_proxy_password_instead() -> None:
    configured = parity.configured_scenarios()
    parser = parse(
        parity.website_monitoring_conf(configured, stored_proxy_password=True)
    )
    assert parser.sections() == ["default", "auth", "ignore", "plain"]
    assert "proxy_password" not in parser["auth"]
    assert parser["auth"]["proxy_user"] == PROXY_USER
    assert parity.passwords(configured, stored_proxy_password=True) == [
        ("website_monitoring_app_proxy", "IN_CONF_FILE", PROXY_PASSWORD)
    ]
    assert parse(parity.website_monitoring_conf())["auth"]["proxy_password"] == (
        PROXY_PASSWORD
    )
    assert parity.passwords(configured) == []


def test_compared_proxy_logs_belong_to_compared_proxy_scenarios() -> None:
    compared = {s.title: s for s in parity.compared_scenarios()}
    for title in parity.PROXIES_COMPARED:
        assert compared[title].conf is not None, title


def test_hosts_pass_the_preflight() -> None:
    hosts = {urlsplit(s.url).hostname for s in PARITY_SCENARIOS}
    assert hosts <= ALLOWED_STANZA_HOSTS


def test_auth_scenarios_use_the_target_credentials() -> None:
    table = parity.by_title()
    assert table["basic-plain"].settings["username"] == server.AUTH_USER
    assert table["basic-plain"].settings["password"] == server.AUTH_PASSWORD
    assert "password" not in table["basic-secure"].settings
    assert parity.passwords() == [
        ("web_ping://basic-secure", server.AUTH_USER, server.AUTH_PASSWORD)
    ]


def test_one_content_scenario_per_target_case() -> None:
    titles = set(parity.by_title())
    assert {f"content-{case}" for case in server.CONTENT_CASES} <= titles


@pytest.mark.parametrize(
    ("title", "port", "path", "expected"),
    [
        ("chain-at-3", 8080, "/chain/chain-at-3/1", True),
        ("status-200", 8080, "/status/200", True),
        ("status-200", 8080, "/status/404", False),
        ("timeout", 8081, "", True),
        ("timeout", 8080, "", False),
        ("tls-valid", 8443, "/tls-valid", True),
        ("tls-valid", 8443, "/proxy-https", False),
        ("refused", 8090, "/", True),
        ("date-in-url", 8080, "/done/d?d=2020-01-02T03:04:05", True),
        ("date-in-url", 8080, "/status/200", False),
        ("status-200", 8080, "/done/d?d=2020-01-02T03:04:05", False),
        ("idn-host", 8080, "/done/idn-host", True),
        ("path-unicode", 8080, "/path/path-unicode/M%C3%BCller?q=M%C3%BCnchen", True),
        ("path-space", 8080, "/path/path-space/a b", True),
        ("cookie-redirect", 8080, "/cookie/cookie-redirect", True),
    ],
)
def test_matches_request(title: str, port: int, path: str, expected: bool) -> None:
    assert parity.by_title()[title].matches_request(port, path) is expected


def test_matches_proxy() -> None:
    table = parity.by_title()
    assert table["proxy-plain"].matches_proxy("http://target:8080/done/proxy-plain")
    assert not table["proxy-plain"].matches_proxy("http://target:8080/done/proxy-auth")
    assert table["proxy-https"].matches_proxy("target:8443")
    assert not table["tls-valid"].matches_proxy("target:8443")


def test_request_scenarios_reach_their_target_routes() -> None:
    routes = {
        title: urlsplit(s.url).path.strip("/").split("/")[0]
        for title, s in parity.by_title().items()
    }
    for route in ("gzip", "gzip-forced", "deflate", "deflate-raw"):
        assert routes[route] == route
        assert (
            parity.by_title()[route].settings["should_contain_string"]
            == "WPTEST-MARKER"
        )
    assert routes["cookie-redirect"] == "cookie"
    assert routes["body-lines"] == "body-lines"
    assert routes["body-binary"] == "body-binary"
    assert parity.by_title()["body-lines"].settings["return_body"] == "1"


def test_international_urls_survive_the_conf_file() -> None:
    parser = parse(parity.inputs_conf())
    assert (
        parser["web_ping://idn-eszett"]["url"]
        == "http://straße.test:8080/done/idn-eszett"
    )
    assert (
        parser["web_ping://path-space"]["url"]
        == "http://target:8080/path/path-space/a b"
    )
    assert parser["web_ping://host-set"]["host"] == "wptest-host"
    assert parser["web_ping://date-in-title"]["title"] == "2020-01-02T03:04:05 check"


def test_pending_names_known_scenarios_and_a_missing_feature() -> None:
    titles = {s.title for s in PARITY_SCENARIOS}
    assert set(parity.PENDING) <= titles
    for title, reason in parity.PENDING.items():
        assert reason.startswith("needs "), title


def test_compared_scenarios_leave_out_pending_and_refused_ones() -> None:
    compared = {s.title for s in parity.compared_scenarios()}
    assert compared.isdisjoint(parity.PENDING)
    assert compared.isdisjoint(parity.REFUSED)
    assert set(parity.PENDING).isdisjoint(parity.REFUSED)
    everything = compared | set(parity.PENDING) | set(parity.REFUSED)
    assert everything == {s.title for s in PARITY_SCENARIOS}


def test_config_app_has_compared_and_refused_scenarios() -> None:
    configured = parity.configured_scenarios()
    stanzas = parse(parity.inputs_conf(configured)).sections()
    assert stanzas == [f"web_ping://{s.title}" for s in configured]
    titles = {s.title for s in configured}
    assert titles == {s.title for s in parity.compared_scenarios()} | set(
        parity.REFUSED
    )


def test_refused_scenarios_are_refused_by_the_settings() -> None:
    for title, message in parity.REFUSED.items():
        scenario = parity.by_title()[title]
        with pytest.raises(ConfigError, match=message):
            _ = build_settings(f"web_ping://{title}", scenario.stanza())


def test_compared_request_logs_belong_to_compared_scenarios() -> None:
    compared = {s.title for s in parity.compared_scenarios()}
    assert set(parity.REQUESTS_COMPARED) <= compared
