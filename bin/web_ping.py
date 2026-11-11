from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence

from logger import log, setup_logging
from ping_check import check_url, event_fields
from ping_config import ConfigError, build_settings
from ping_events import write_event

SCHEME = """<scheme>
  <title>Web Ping</title>
  <description>Checks a URL and records response code and timing.</description>
  <use_external_validation>false</use_external_validation>
  <use_single_instance>false</use_single_instance>
  <streaming_mode>xml</streaming_mode>
  <endpoint>
    <args>
      <arg name="url"><title>URL</title><description>URL to check</description><required_on_create>true</required_on_create></arg>
      <arg name="title"><title>Title</title><required_on_create>false</required_on_create></arg>
      <arg name="timeout"><title>Timeout</title><required_on_create>false</required_on_create></arg>
      <arg name="user_agent"><title>User agent</title><required_on_create>false</required_on_create></arg>
      <arg name="max_redirects"><title>Max redirects</title><required_on_create>false</required_on_create></arg>
      <arg name="log_level"><title>Log level</title><required_on_create>false</required_on_create></arg>
    </args>
  </endpoint>
</scheme>
"""


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
    if not setup_logging(params.get("log_level", "INFO"), name):
        log.warning("invalid log_level %r, using INFO", params.get("log_level"))
    settings = build_settings(params)
    log.debug("effective settings: %s", settings)
    log.info("starting check url=%s", settings["url"])
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
            _ = sys.stdout.write(SCHEME)
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
