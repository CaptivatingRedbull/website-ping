from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from xml.sax.saxutils import escape

from logger import log, setup_logging
from ping_check import check_url, event_fields
from ping_config import ConfigError, build_settings
from ping_events import write_event
from wp_version import runtime_versions

SCHEME_ARGS: tuple[tuple[str, str, str], ...] = (
    ("url", "URL", "The URL to check (http or https)"),
    ("title", "Title", "A short description of the site; defaults to the URL"),
    ("configuration", "Configuration",
     "Stanza of website_monitoring.conf to use; defaults to default"),
    ("client_certificate", "Client certificate", "Path to a client certificate"),
    ("client_certificate_key", "Client certificate key",
     "Path to the client certificate key, if it is not in the certificate file"),
    ("username", "Username", "User name for HTTP authentication"),
    ("password", "Password",
     "Not supported, rejected; store the password in storage/passwords"),
    ("user_agent", "User agent", "User-Agent header to send"),
    ("should_contain_string", "String match", "Text expected in the response body"),
    ("max_redirects", "Maximum redirects",
     "Redirects to follow; -1 or blank for unlimited, 0 to follow none"),
    ("timeout", "Timeout", "Seconds to wait for a response; defaults to 30"),
    ("return_body", "Return response body", "true or 1 to index the response body"),
    ("return_headers", "Return headers", "true or 1 to add the response headers"),
    ("warning_threshold", "Warning threshold",
     "Response time in ms above which the check counts as a warning"),
    ("error_threshold", "Error threshold",
     "Response time in ms above which the check counts as failed"),
    ("ssl_verify", "Verify certificates",
     "true or 1 to verify the server certificate"),
    ("ca_certs", "CA certificates", "Path to a CA bundle for certificate checks"),
    ("log_level", "Log level", "DEBUG, INFO, WARN or ERROR; defaults to INFO"),
)  # fmt: skip
"""Arguments declared in the scheme. interval is not declared: splunkd refuses to
start a multi-instance input whose scheme declares it."""


def scheme_xml() -> str:
    args = "\n".join(
        f'      <arg name="{name}"><title>{escape(title)}</title>'
        f"<description>{escape(description)}</description>"
        f"<required_on_create>{'true' if name == 'url' else 'false'}</required_on_create>"
        "<required_on_edit>false</required_on_edit></arg>"
        for name, title, description in SCHEME_ARGS
    )
    return (
        "<scheme>\n"
        "  <title>Web Ping</title>\n"
        "  <description>Checks a URL and records response code and timing.</description>\n"
        "  <use_external_validation>false</use_external_validation>\n"
        "  <use_single_instance>false</use_single_instance>\n"
        "  <streaming_mode>xml</streaming_mode>\n"
        "  <endpoint>\n"
        "    <args>\n"
        f"{args}\n"
        "    </args>\n"
        "  </endpoint>\n"
        "</scheme>\n"
    )


def read_config(xml_text: str) -> tuple[str, dict[str, str]]:
    """Return (stanza_name, params) from the XML splunkd sends on stdin."""
    root = ET.fromstring(xml_text)
    stanza = root.find("configuration/stanza")
    name = stanza.get("name") if stanza is not None else None
    if stanza is None or not name:
        raise ValueError("no stanza in input configuration")
    params = {
        key: (p.text or "").strip()
        for p in stanza.findall("param")
        if (key := p.get("name"))
    }
    return name, params


def ping() -> None:
    name, params = read_config(sys.stdin.read())
    _ = setup_logging("INFO", name)
    # splunkd still schedules each stanza itself, so interval may be absent or in a
    # form only splunkd parses.
    settings, warnings = build_settings(name, params, require_interval=False)
    _ = setup_logging(settings["log_level"], name)
    for warning in warnings:
        log.warning("%s", warning)
    log.debug("effective settings: %s", settings)
    log.info("starting check url=%s %s", settings["url"], runtime_versions())
    result = check_url(settings)
    log.info(
        "check done code=%d time=%.3f timed_out=%s",
        result.response_code,
        result.total_time,
        result.timed_out,
    )
    if result.error:
        log.warning("check failed: %s", result.error)
    write_event(event_fields(settings, result))


def main(argv: Sequence[str]) -> int:
    _ = setup_logging()
    if len(argv) > 1:
        if argv[1] == "--scheme":
            _ = sys.stdout.write(scheme_xml())
            return 0
        if argv[1] == "--validate-arguments":
            return 0
        log.error("unkown argument %s", argv[1])
        return 1
    ping()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ConfigError as e:
        log.error("invalid configuration: %s", e)
        sys.exit(1)

    except Exception:  # noqa: BLE001 - last resort, the process must log and exit 1
        log.exception("unhandled error")
        sys.exit(1)
