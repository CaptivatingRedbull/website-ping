from __future__ import annotations

import configparser
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from web_ping import SCHEME_ARGS, scheme_xml
from wp_splunk import DEFAULTS_STANZA

ROOT = Path(__file__).absolute().parent.parent
SPEC = ROOT / "README" / "inputs.conf.spec"
CONF_SPEC = ROOT / "README" / "website_monitoring.conf.spec"
CONF_DEFAULT = ROOT / "default" / "website_monitoring.conf"
WEBSITE_MONITORING_CONF_KEYS = {
    "proxy_server", "proxy_port", "proxy_user", "proxy_password", "proxy_type",
    "proxy_ignore", "thread_limit", "max_response_body_length", "ssl_verify",
    "ca_certs",
}  # fmt: skip


def spec_keys() -> set[str]:
    text = SPEC.read_text(encoding="utf-8")
    return set(re.findall(r"^([a-z_.]+) = ", text, re.MULTILINE))


def scheme_args() -> dict[str, ET.Element]:
    root = ET.fromstring(scheme_xml())
    return {arg.get("name", ""): arg for arg in root.iter("arg")}


def test_scheme_is_single_instance_and_valid_xml() -> None:
    root = ET.fromstring(scheme_xml())
    assert root.findtext("use_single_instance") == "true"
    assert root.findtext("streaming_mode") == "xml"


def test_interval_declared_in_scheme() -> None:
    assert "interval" in scheme_args()


def test_url_and_interval_required() -> None:
    required = {
        name
        for name, arg in scheme_args().items()
        if arg.findtext("required_on_create") == "true"
    }
    assert required == {"url", "interval"}


def test_spec_covers_every_scheme_arg() -> None:
    assert spec_keys() == {name for name, _, _ in SCHEME_ARGS}


def test_every_website_monitoring_key_declared() -> None:
    old_keys = {
        "url", "title", "configuration", "client_certificate",
        "client_certificate_key", "username", "password", "user_agent",
        "should_contain_string", "max_redirects", "timeout", "return_body",
        "return_headers", "warning_threshold", "error_threshold",
    }  # fmt: skip
    assert old_keys <= set(scheme_args())


def test_website_monitoring_spec_declares_every_key() -> None:
    text = CONF_SPEC.read_text(encoding="utf-8")
    keys = set(re.findall(r"^([a-z_.]+) = ", text, re.MULTILINE))
    assert keys == WEBSITE_MONITORING_CONF_KEYS


@pytest.mark.parametrize("spec", [SPEC, CONF_SPEC], ids=lambda path: path.name)
def test_no_spec_line_reads_as_a_setting(spec: Path) -> None:
    """splunkd takes an indented line that starts with key=value for a setting."""
    lines = spec.read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if re.match(r"\s+[A-Za-z_.]+ ?=", line)] == []


def test_default_website_monitoring_conf_sets_no_value() -> None:
    """Only the empty stanza [default] is read through; a value here would rank
    above the same setting in another app's website_monitoring.conf."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(CONF_DEFAULT, encoding="utf-8")
    assert parser.sections() == [DEFAULTS_STANZA]
    assert dict(parser[DEFAULTS_STANZA]) == {}
