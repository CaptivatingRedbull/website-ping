from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from web_ping import SCHEME_ARGS, scheme_xml

SPEC = Path(__file__).absolute().parent.parent / "README" / "inputs.conf.spec"


def spec_keys() -> set[str]:
    text = SPEC.read_text(encoding="utf-8")
    return set(re.findall(r"^([a-z_.]+) = ", text, re.MULTILINE))


def scheme_args() -> dict[str, ET.Element]:
    root = ET.fromstring(scheme_xml())
    return {arg.get("name", ""): arg for arg in root.iter("arg")}


def test_scheme_is_multi_instance_and_valid_xml() -> None:
    root = ET.fromstring(scheme_xml())
    assert root.findtext("use_single_instance") == "false"
    assert root.findtext("streaming_mode") == "xml"


def test_interval_not_declared_in_scheme() -> None:
    assert "interval" not in scheme_args()


def test_only_url_required() -> None:
    required = {
        name
        for name, arg in scheme_args().items()
        if arg.findtext("required_on_create") == "true"
    }
    assert required == {"url"}


def test_spec_covers_every_scheme_arg_and_interval() -> None:
    assert spec_keys() == {name for name, _, _ in SCHEME_ARGS} | {"interval"}


def test_every_website_monitoring_key_declared() -> None:
    old_keys = {
        "url", "title", "configuration", "client_certificate",
        "client_certificate_key", "username", "password", "user_agent",
        "should_contain_string", "max_redirects", "timeout", "return_body",
        "return_headers", "warning_threshold", "error_threshold",
    }  # fmt: skip
    assert old_keys <= set(scheme_args())
