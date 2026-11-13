"""The parity scenario table and the legacy config generated from it (wptest/parity.py)."""

from __future__ import annotations

import configparser
from urllib.parse import urlsplit

import pytest
from target import server
from wptest import parity
from wptest.parity import PARITY_SCENARIOS, ParityScenario
from wptest.preflight import ALLOWED_STANZA_HOSTS


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
