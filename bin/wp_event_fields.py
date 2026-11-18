"""The events of one check, in the order and form Website Monitoring 2.9.7 used."""

from __future__ import annotations

from ping_check import CheckResult
from ping_config import Settings
from ping_events import Field, format_data, format_event


def event_fields(settings: Settings, result: CheckResult) -> list[Field]:
    """The key=value pairs of the check event.

    Without a complete response, response_code and both times are empty strings,
    as in 2.9.7, so searches for response_code="" keep working. error is added
    last and only on failure.
    """
    code = result.response_code
    elapsed_ms: float | str = (
        round(result.elapsed * 1000, 2) if code is not None else ""
    )
    fields: list[Field] = [
        ("response_code", code if code is not None else ""),
        ("total_time", elapsed_ms),
        ("request_time", elapsed_ms),
        ("timed_out", result.timed_out),
        ("title", settings["title"]),
        ("url", settings["url"]),
        ("timeout", settings["timeout"]),
    ]
    for name, value in result.headers or ():
        fields.append((f"header_{name}", value))
    proxy = result.proxy
    fields += [("proxy_server", proxy.server), ("proxy_type", proxy.type)]
    if proxy.user:
        fields.append(("proxy_user", proxy.user))
    fields.append(("proxy_port", proxy.port))
    if result.content_md5 is not None:
        fields.append(("content_md5", result.content_md5))
    if result.content_sha224 is not None:
        fields.append(("content_sha224", result.content_sha224))
    if result.content_size is not None:
        fields.append(("content_size", result.content_size))
    if result.has_expected_string is not None:
        fields.append(("has_expected_string", str(result.has_expected_string).lower()))
    if result.exceeded_redirects:
        fields.append(("exceeded_redirects", True))
    if settings["max_redirects"] is not None:
        fields.append(("max_redirects", settings["max_redirects"]))
    if settings["warning_threshold"] is not None:
        fields.append(("warning_threshold", settings["warning_threshold"]))
    if settings["error_threshold"] is not None:
        fields.append(("error_threshold", settings["error_threshold"]))
    if result.error:
        fields.append(("error", result.error))
    return fields


def check_event(settings: Settings, result: CheckResult) -> str:
    """The complete XML of the check event; its time is the end of the check."""
    return format_event(
        settings["stanza"],
        format_data(event_fields(settings, result)),
        time=result.finished,
        sourcetype=settings["sourcetype"],
        source=settings["stanza"],
        index=settings["index"],
        host=settings["host"],
    )


def body_event(settings: Settings, result: CheckResult) -> str | None:
    """The XML of the body event, or None when the check has no body to return.

    Sourcetype <sourcetype>:response; source, index, host and time as in the
    check event. The text is the body as decoded; format_event removes the
    characters XML forbids, so a binary body cannot break the stream. An empty
    body gives no event: Splunk does not index an event without text.
    """
    if not result.body:
        return None
    return format_event(
        settings["stanza"],
        result.body,
        time=result.finished,
        sourcetype=f"{settings['sourcetype']}:response",
        source=settings["stanza"],
        index=settings["index"],
        host=settings["host"],
    )


def check_events(settings: Settings, result: CheckResult) -> str:
    """Everything one check writes, as one text for one write: the body event
    first, as 2.9.7 wrote it, then the check event."""
    body = body_event(settings, result)
    check = check_event(settings, result)
    return check if body is None else body + check
