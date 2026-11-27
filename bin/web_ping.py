from __future__ import annotations

import contextlib
import os
import signal
import sys
from collections.abc import Mapping, Sequence
from xml.sax.saxutils import escape

from logger import CONSOLE, flush_logging, process_log, setup_logging, stanza_logger
from ping_check import CheckResult, check_url
from ping_config import ConfigError, Settings, build_settings
from ping_events import write_event
from wp_context import CheckContext, ConfigContexts
from wp_deadline import Phases
from wp_event_fields import check_events
from wp_names import CONF_FILE
from wp_runner import STOP_WAIT, Checkpoints, Runner, read_input_config
from wp_splunk import DEFAULT_THREAD_LIMIT, ConfigCache, RestClient, SplunkdClient
from wp_version import runtime_versions

SCHEME_ARGS: tuple[tuple[str, str, str], ...] = (
    ("url", "URL", "The URL to check (http or https)"),
    ("interval", "Interval",
     "How often to check: a number with an optional unit, such as 30s, 15m, 2h, 1d"),
    ("title", "Title", "A short description of the site; defaults to the URL"),
    ("configuration", "Configuration",
     f"Stanza of {CONF_FILE} to use; defaults to default"),
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
"""Arguments declared in the scheme, as Website Monitoring 2.9.7 declared them.

The input is single-instance: one process gets every stanza and schedules them by
their interval itself, so splunkd accepts interval as a declared argument.
"""

REQUIRED_ARGS = frozenset({"url", "interval"})


def scheme_xml() -> str:
    args = "\n".join(
        f'      <arg name="{name}"><title>{escape(title)}</title>'
        f"<description>{escape(description)}</description>"
        f"<required_on_create>{'true' if name in REQUIRED_ARGS else 'false'}"
        "</required_on_create>"
        "<required_on_edit>false</required_on_edit></arg>"
        for name, title, description in SCHEME_ARGS
    )
    return (
        "<scheme>\n"
        "  <title>Web Ping</title>\n"
        "  <description>Checks a URL and records response code and timing.</description>\n"
        "  <use_external_validation>false</use_external_validation>\n"
        "  <use_single_instance>true</use_single_instance>\n"
        "  <streaming_mode>xml</streaming_mode>\n"
        "  <endpoint>\n"
        "    <args>\n"
        f"{args}\n"
        "    </args>\n"
        "  </endpoint>\n"
        "</scheme>\n"
    )


def load_settings(
    stanzas: Mapping[str, Mapping[str, str]],
) -> tuple[list[Settings], int]:
    """Settings of every valid stanza and the number of invalid ones. Each invalid
    stanza is logged as one ERROR and not run; the others run."""
    valid: list[Settings] = []
    invalid = 0
    for name, params in stanzas.items():
        try:
            settings, warnings = build_settings(name, params)
        except ConfigError as exc:
            stanza_logger(name).error("invalid configuration, not run: %s", exc)
            invalid += 1
            continue
        slog = stanza_logger(name, settings["log_level"])
        for warning in warnings:
            slog.warning("%s", warning)
        slog.debug("effective settings: %s", settings)
        valid.append(settings)
    return valid, invalid


def run_check(context: CheckContext, phases: Phases) -> CheckResult:
    settings = context.settings
    slog = stanza_logger(settings["stanza"], settings["log_level"])
    slog.info("starting check url=%s", settings["url"])
    result = check_url(context, phases)
    slog.info(
        "check done code=%s time=%.3f timed_out=%s",
        result.response_code,
        result.elapsed,
        result.timed_out,
    )
    if result.error:
        slog.warning("check failed: %s", result.error)
    return result


def write_to_stdout(event: str) -> None:
    write_event(event, sys.stdout)


def build_runner(xml_text: str, client: SplunkdClient | None = None) -> Runner:
    """The Runner for the configuration splunkd sent; logs the start line.

    website_monitoring.conf and storage/passwords are read through client, by
    default splunkd's REST API with the session key from xml_text.
    """
    config = read_input_config(xml_text)
    settings, invalid = load_settings(config.stanzas)
    cache = ConfigCache(client or RestClient(config.session_key))
    snapshot = cache.refresh_if_due()
    if snapshot is None:
        # The thread pool is sized once; a later load cannot change it.
        thread_limit = DEFAULT_THREAD_LIMIT
        process_log.error(
            "thread_limit of %s not known, using %d until the input restarts",
            CONF_FILE,
            thread_limit,
        )
    else:
        thread_limit = snapshot.app.thread_limit
    process_log.info(
        "starting stanzas=%d invalid=%d thread_limit=%d pid=%d %s",
        len(settings),
        invalid,
        thread_limit,
        os.getpid(),
        runtime_versions(),
        extra=CONSOLE,
    )
    if not settings:
        # Exiting would go unnoticed: splunkd starts the input again only after a
        # configuration change or a restart, which brings a new process anyway.
        process_log.warning("no valid stanza, idle until splunkd restarts the input")
    return Runner(
        settings,
        run_check,
        check_events,
        write_to_stdout,
        Checkpoints(config.checkpoint_dir),
        thread_limit=thread_limit,
        contexts=ConfigContexts(cache),
    )


def serve(runner: Runner) -> str:
    """Run until a signal, a closed stdout or a lost parent stops the runner, then
    shut down within STOP_WAIT seconds. Returns the stop reason."""
    for signum in (signal.SIGTERM, signal.SIGINT):
        _ = signal.signal(signum, runner.on_signal)
    reason = runner.run()
    process_log.info("stopping reason=%s pid=%d", reason, os.getpid())
    running = runner.shutdown(STOP_WAIT)
    process_log.info(
        "stopped reason=%s pid=%d abandoned=%d",
        reason,
        os.getpid(),
        running,
        extra=CONSOLE,
    )
    return reason


def main(argv: Sequence[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--scheme":
            _ = sys.stdout.write(scheme_xml())
            return 0
        if argv[1] == "--validate-arguments":
            return 0
        process_log.error("unknown argument %s", argv[1])
        return 1
    _ = setup_logging()
    _ = serve(build_runner(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    try:
        code = main(sys.argv)
    except Exception:  # noqa: BLE001 - last resort, the process must log and exit 1
        process_log.exception("unhandled error")
        code = 1
    flush_logging()
    for stream in (sys.stdout, sys.stderr):
        # os._exit below skips Python's own flush, which would drop the --scheme
        # output. stdout is already closed when splunkd stops the input.
        with contextlib.suppress(OSError, ValueError):
            stream.flush()
    # os._exit: the thread pool's workers would otherwise be joined at exit and could
    # hold the process until splunkd kills it.
    os._exit(code)
