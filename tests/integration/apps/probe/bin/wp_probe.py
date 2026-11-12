"""Throwaway single-instance modular input. Never shipped.

Logs to stderr, one line per record, prefixed PROBE. Never logs the session key
or a password, only their lengths and names.
"""

from __future__ import annotations

import importlib
import json
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from types import FrameType
from typing import Optional, cast
from xml.sax.saxutils import escape, quoteattr

SINGLE_INSTANCE = True
SCHEME = "wp_probe"
TICK = 10.0
HARNESS_CA = "/tmp/wptest-ca.pem"
ARGS = ("url", "interval", "title", "configuration", "exit_after", "sigterm_delay")
REST_PATHS = (
    "/servicesNS/nobody/-/configs/conf-website_monitoring?output_mode=json&count=0",
    "/services/storage/passwords?output_mode=json&count=0",
)

Stanzas = dict[str, dict[str, str]]


def log(message: str) -> None:
    sys.stderr.write(f"PROBE {message}\n")
    sys.stderr.flush()


def scheme() -> str:
    names = ARGS if SINGLE_INSTANCE else tuple(a for a in ARGS if a != "interval")
    args = "".join(
        f'<arg name="{name}"><title>{name}</title>'
        "<required_on_create>false</required_on_create></arg>"
        for name in names
    )
    single = "true" if SINGLE_INSTANCE else "false"
    return (
        "<scheme><title>wp_probe</title>"
        "<description>website-ping single-instance probe</description>"
        f"<use_external_validation>false</use_external_validation>"
        f"<use_single_instance>{single}</use_single_instance>"
        "<streaming_mode>xml</streaming_mode>"
        f"<endpoint><args>{args}</args></endpoint></scheme>"
    )


def read_input(text: str) -> tuple[dict[str, str], Stanzas]:
    """Header values (session_key replaced by its length) and stanza params."""
    root = ET.fromstring(text)
    header: dict[str, str] = {}
    stanzas: Stanzas = {}
    for child in root:
        if child.tag == "configuration":
            for stanza in child.findall("stanza"):
                params: dict[str, str] = {
                    f"@{key}": value for key, value in stanza.attrib.items()
                }
                for param in stanza:
                    name = param.get("name", "?")
                    if param.tag == "param_list":
                        params[name] = "|".join(v.text or "" for v in param)
                    else:
                        params[name] = param.text or ""
                stanzas[stanza.get("name", "?")] = params
        elif child.tag == "session_key":
            header["session_key.length"] = str(len(child.text or ""))
        else:
            header[child.tag] = child.text or ""
    return header, stanzas


def log_environment() -> None:
    log(f"pid={os.getpid()} ppid={os.getppid()}")
    log(f"python={sys.version.replace(chr(10), ' ')} executable={sys.executable}")
    log(f"openssl={ssl.OPENSSL_VERSION}")
    paths = ssl.get_default_verify_paths()
    for name in ("cafile", "capath", "openssl_cafile", "openssl_capath"):
        value = cast(Optional[str], getattr(paths, name))
        exists = bool(value) and os.path.exists(value or "")
        log(f"verify_paths.{name}={value} exists={exists}")
    for key in sorted(os.environ):
        if "proxy" in key.lower():
            log(f"env {key} set (value not logged)")
        elif key.startswith(("PYTHON", "SSL_", "REQUESTS_")):
            log(f"env {key}={os.environ[key]}")


def log_rest(session_key: str, server_uri: str) -> None:
    """Question 8: the splunk package first, then plain urllib as a cross-check."""
    try:
        rest = importlib.import_module("splunk.rest")
        simple_request = cast("Callable[..., tuple[object, bytes]]", rest.simpleRequest)
    except Exception as exc:  # noqa: BLE001 - the answer is whether it works
        log(f"rest.import failed: {type(exc).__name__}: {exc}")
        simple_request = None
    for path in REST_PATHS:
        if simple_request is not None:
            try:
                response, content = simple_request(path, sessionKey=session_key)
                status = getattr(response, "status", "?")
                log(f"rest.splunk path={path.split('?')[0]} status={status}")
                log_entries(path, content)
            except Exception as exc:  # noqa: BLE001
                log(f"rest.splunk path={path.split('?')[0]} failed: {exc}")
        log_urllib(server_uri, path, session_key)


def log_urllib(server_uri: str, path: str, session_key: str) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(
        server_uri + path, headers={"Authorization": f"Splunk {session_key}"}
    )
    try:
        with opener.open(request, timeout=30) as response:
            content = cast(bytes, response.read())
            log(f"rest.urllib path={path.split('?')[0]} status={response.status}")
    except urllib.error.HTTPError as exc:
        log(f"rest.urllib path={path.split('?')[0]} status={exc.code}")
        return
    except Exception as exc:  # noqa: BLE001
        log(f"rest.urllib path={path.split('?')[0]} failed: {exc}")
        return
    log_entries(path, content)


def log_entries(path: str, content: bytes) -> None:
    """Entry names, and for conf stanzas the keys and values (no secrets there)."""
    try:
        entries = cast(
            "list[dict[str, object]]", json.loads(content.decode()).get("entry", [])
        )
    except ValueError:
        log(f"rest.entries path={path.split('?')[0]} not JSON")
        return
    for entry in entries:
        name = entry.get("name")
        body = cast("dict[str, object]", entry.get("content", {}))
        acl = cast("dict[str, object]", entry.get("acl", {}))
        if "storage/passwords" in path:
            log(
                f"rest.password name={name} realm={body.get('realm')}"
                f" username={body.get('username')} app={acl.get('app')}"
                f" clear_password.length={len(str(body.get('clear_password', '')))}"
            )
        else:
            settings = {
                k: v
                for k, v in body.items()
                if not k.startswith("eai:") and k != "disabled"
            }
            log(f"rest.conf stanza={name} app={acl.get('app')} settings={settings}")


def log_tls(url: str) -> None:
    """Question 9: default context, then the harness CA, no proxy."""
    if not url.startswith("https://"):
        return
    for label, cafile in (("default", None), ("harness_ca", HARNESS_CA)):
        if cafile is not None and not os.path.exists(cafile):
            log(f"tls.{label} skipped: {cafile} missing")
            continue
        context = ssl.create_default_context(cafile=cafile)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        try:
            with opener.open(url, timeout=10) as response:
                log(f"tls.{label} url={url} status={response.status}")
        except urllib.error.HTTPError as exc:
            log(f"tls.{label} url={url} status={exc.code} (handshake ok)")
        except Exception as exc:  # noqa: BLE001
            log(f"tls.{label} url={url} failed: {type(exc).__name__}: {exc}")


def event(stanza: str, pid: int) -> str:
    name = f"{SCHEME}://{stanza}"
    data = escape(f"probe stanza={stanza} pid={pid}")
    return f"<event stanza={quoteattr(name)}><data>{data}</data></event>"


def sigterm_delay(stanzas: Mapping[str, Mapping[str, str]]) -> float:
    values = [
        float(p["sigterm_delay"]) for p in stanzas.values() if p.get("sigterm_delay")
    ]
    return max(values, default=0.0)


def sigterm_handler(delay: float) -> Callable[[int, FrameType | None], None]:
    """Question 6: stay alive delay seconds after SIGTERM, to see when SIGKILL comes."""

    def on_sigterm(_signum: int, _frame: FrameType | None) -> None:
        pid = os.getpid()
        log(f"sigterm pid={pid} delay={delay:.0f} wall={time.time():.3f}")
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            time.sleep(1)
            log(f"sigterm still alive pid={pid} wall={time.time():.3f}")
        try:
            sys.stdout.write("</stream>\n")
            sys.stdout.flush()
        except BrokenPipeError:
            log(f"sigterm stdout already closed pid={pid}")
        os._exit(0)

    return on_sigterm


def exit_after(stanzas: Mapping[str, Mapping[str, str]]) -> float | None:
    values = [float(p["exit_after"]) for p in stanzas.values() if p.get("exit_after")]
    return min(values) if values else None


def run(text: str) -> int:
    started = time.monotonic()
    log(f"start pid={os.getpid()} ppid={os.getppid()} wall={time.time():.3f}")
    header, stanzas = read_input(text)
    signal.signal(signal.SIGTERM, sigterm_handler(sigterm_delay(stanzas)))
    for key, value in sorted(header.items()):
        log(f"header {key}={value}")
    log(f"stanzas count={len(stanzas)} names={sorted(stanzas)}")
    for name, params in sorted(stanzas.items()):
        log(f"stanza {name} params={dict(sorted(params.items()))}")
    log_environment()
    session_key = (
        (ET.fromstring(text).findtext("session_key") or "") if text.strip() else ""
    )
    if session_key:
        log_rest(session_key, header.get("server_uri", "https://127.0.0.1:8089"))
    for params in stanzas.values():
        log_tls(params.get("url", ""))
    limit = exit_after(stanzas)
    pid = os.getpid()
    sys.stdout.write("<stream>\n")
    while True:
        if os.getppid() == 1:
            log(f"orphaned pid={pid}, exit 2")
            return 2
        for name in sorted(stanzas):
            short = name.split("://", 1)[-1]
            sys.stdout.write(event(short, pid) + "\n")
        sys.stdout.flush()
        if limit is not None and time.monotonic() - started >= limit:
            log(f"exit_after={limit:.0f} reached pid={pid}, exit 0")
            sys.stdout.write("</stream>\n")
            sys.stdout.flush()
            return 0
        time.sleep(TICK)


def main(argv: list[str]) -> int:
    if argv[1:2] == ["--scheme"]:
        sys.stdout.write(scheme())
        return 0
    if argv[1:2] == ["--validate-arguments"]:
        return 0
    return run(sys.stdin.read())


if __name__ == "__main__":
    sys.exit(main(sys.argv))
