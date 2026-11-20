"""Knowledge objects keep Website Monitoring 2.9.7's names and content, so
searches, alerts and local/ overrides written for it keep working."""

from __future__ import annotations

import csv
import hashlib
import io
import tarfile
from pathlib import Path

import logger
import pytest
import wp_runner
from wptest import conf, legacy
from wptest.conf import Conf, parse_conf

ROOT = Path(__file__).absolute().parent.parent
LEGACY = ROOT / "tests" / "fixtures" / "website_monitoring_2.9.7"
"""Copies of Website Monitoring 2.9.7's default/macros.conf and savedsearches.conf."""

LOOKUP = ROOT / "lookups" / "http_response_codes.csv"
LOOKUP_SHA256 = "017cc72291aa6655bb2d60dde170e0f76057a07471da710a3593416b3bcc8947"
"""SHA-256 of Website Monitoring 2.9.7's lookups/http_response_codes.csv, which
has no newline after its last row."""


def read_conf(relative: str) -> Conf:
    return conf.read_conf(ROOT / relative)


def test_lookup_is_website_monitorings_table() -> None:
    """Byte for byte 2.9.7's file; a final newline added by an editor is allowed."""
    data = LOOKUP.read_bytes()
    assert hashlib.sha256(data.rstrip(b"\n")).hexdigest() == LOOKUP_SHA256
    rows = list(csv.DictReader(io.StringIO(data.decode("ascii"))))
    assert list(rows[0]) == ["response_code", "title", "description"]
    descriptions = {row["response_code"]: row["description"] for row in rows}
    assert descriptions["503"] == "Service Unavailable"


def test_lookup_definition() -> None:
    assert read_conf("default/transforms.conf") == {
        "http_response_codes": {"filename": "http_response_codes.csv"}
    }


def test_eventtype_and_tag_that_exclude_sites_from_the_alert() -> None:
    """The placeholder search is replaced in local/eventtypes.conf by the user."""
    assert read_conf("default/eventtypes.conf") == {
        "filter_website_monitoring_alerts": {"search": "FILL_THIS_SEARCH_IN"}
    }
    assert read_conf("default/tags.conf") == {
        "eventtype=filter_website_monitoring_alerts": {"exclude_from_alerts": "enabled"}
    }


def test_every_object_is_exported_and_thresholds_are_writable_by_power() -> None:
    meta = read_conf("metadata/default.meta")
    assert meta.pop("") == {
        "access": "read : [ * ], write : [ admin, sc_admin ]",
        "export": "system",
    }
    for kind in (
        "eventtypes",
        "lookups",
        "macros",
        "props",
        "savedsearches",
        "tags",
        "transforms",
    ):
        assert meta.pop(kind) == {"export": "system"}, kind
    for macro in (
        "response_codes_to_alert_on",
        "response_time_threshold",
        "response_time_threshold_warning",
    ):
        assert meta.pop(f"macros/{macro}") == {
            "access": "read : [ * ], write : [ admin, power ]",
            "export": "system",
        }, macro
    assert meta == {}


# ---- macros and saved searches ---------------------------------------------------

FILLNULL = 'fillnull response_code value="Connection failed"'
"""2.9.7's way to name a failed connection. It never fires: a check without a
response writes response_code="" (set, not null), and fillnull fills only null."""
EMPTY_IS_FAILED = (
    'eval response_code=if(isnull(response_code) OR response_code=="",'
    ' "Connection failed", response_code)'
)

MACROS = {
    "response_time_threshold",
    "response_time_threshold_warning",
    "timesince(2)",
    "duration(3)",
    "format_events",
    "format_events_raw",
    "format_events_ex",
    "filter_inoperable",
    "filter_disabled",
    "response_codes_to_alert_on",
    "filter_response_codes_and_response_times",
    "website_monitoring_search_index",
    "set_response_code",
    "set_status",
}
SAVED_SEARCHES = {
    "website_availability_overview",
    "website_performance_problems",
    "inoperable_sites_rangemap",
    "slow_sites_rangemap",
    "slow_sites_avg_rangemap",
    "Website Performance Problem",
    "Website Ping Runner Silent",
}


def continued(*lines: str) -> str:
    """A multi-line setting as parse_conf returns it: lines written with a
    trailing " \\" in the file, joined by a line break."""
    return " \n".join(lines)


ALERT_SEARCH = continued(
    (
        'sourcetype="web_ping" `website_monitoring_search_index`'
        ' tag!="exclude_from_alerts" (`response_codes_to_alert_on` OR timed_out=True'
        ' OR total_time>`response_time_threshold` OR response_code=""'
        ' OR has_expected_string="false")'
    ),
    '| fillnull value="" has_expected_string',
    (
        "| stats count as count max(total_time) as max_total_time"
        ' max(eval(if(timed_out=="True",1,0))) as timed_out'
        " by title url response_code has_expected_string"
    ),
    "| lookup http_response_codes.csv response_code OUTPUT description",
    '| eval description=response_code." (".description.")"',
    '| eval description=if(response_code == "", "Connection failed", description)',
    '| eval description=if(timed_out == 1, "Connection timed out", description)',
    (
        '| eval description=if(has_expected_string == "false",'
        ' "Content doesn\'t match", description)'
    ),
    '| eval max_total_time=round(max_total_time, 2)." ms"',
    "| fields - has_expected_string timed_out",
)

RUNNER_SILENT = {
    "description": (
        "Triggers for each host whose website-ping runner wrote no heartbeat in the"
        " last 10 minutes after writing one in the last 24 hours: its checks have"
        " stopped, or the host no longer runs website-ping. Look at website_ping.log"
        " on that host; restarting Splunk there starts the runner again."
    ),
    "alert.track": "1",
    "counttype": "number of events",
    "cron_schedule": "*/10 * * * *",
    "dispatch.earliest_time": "-24h",
    "dispatch.latest_time": "now",
    "enableSched": "1",
    "quantity": "0",
    "relation": "greater than",
    "request.ui_dispatch_app": "website_ping",
    "request.ui_dispatch_view": "search",
    "search": continued(
        "index=_internal source=*website_ping.log* heartbeat earliest=-24h",
        "| stats latest(_time) as last_heartbeat by host",
        '| where last_heartbeat < relative_time(now(), "-10m")',
        "| convert ctime(last_heartbeat)",
    ),
}


def legacy_conf(name: str) -> Conf:
    return parse_conf((LEGACY / name).read_text(encoding="utf-8"))


def replaced(text: str, old: str, new: str) -> str:
    """text with old, which must occur exactly once, replaced by new."""
    assert text.count(old) == 1, old
    return text.replace(old, new)


def expected_macros() -> Conf:
    """2.9.7's macros with the documented changes."""
    macros = legacy_conf("macros.conf")
    for name in ("format_events", "format_events_raw", "format_events_ex"):
        macro = macros[name]
        macro["definition"] = replaced(macro["definition"], FILLNULL, EMPTY_IS_FAILED)
    # The lookup it joined is not shipped; the pass-through keeps its callers running.
    macros["filter_disabled"]["definition"] = "| search *"
    return macros


def expected_saved_searches() -> Conf:
    """2.9.7's saved searches with the documented changes."""
    searches = legacy_conf("savedsearches.conf")
    del searches["web_ping_inputs_lookup_gen"]

    overview = searches["website_availability_overview"]
    overview["search"] = replaced(overview["search"], FILLNULL, EMPTY_IS_FAILED)

    problems = searches["website_performance_problems"]
    problems["search"] = replaced(
        replaced(problems["search"], FILLNULL, EMPTY_IS_FAILED),
        "total_time>`response_time_threshold`)",
        'total_time>`response_time_threshold` OR response_code="")',
    )

    inoperable = searches["inoperable_sites_rangemap"]
    inoperable["search"] = replaced(
        inoperable["search"],
        'eval down=if(response_code>=400,1,if(timed_out=="True", 1, 0) )',
        'eval down=if(response_code>=400 OR timed_out=="True"'
        ' OR isnull(response_code) OR response_code=="", 1, 0)',
    )

    alert = searches["Website Performance Problem"]
    alert["description"] = replaced(
        alert["description"],
        'You can edit what is considered a failure from the "Status Overview"'
        " dashboard.",
        "Edit the macros response_codes_to_alert_on and response_time_threshold to"
        " change what is considered a failure.",
    )
    alert["request.ui_dispatch_app"] = "website_ping"
    search = replaced(
        alert["search"],
        "max(total_time) as max_total_time by",
        'max(total_time) as max_total_time max(eval(if(timed_out=="True",1,0)))'
        " as timed_out by",
    )
    search = replaced(
        search,
        '| eval description=if(timed_out == "True", "Connection timed out",'
        " description) \n"
        '| eval description=if(response_code == "", "Connection failed", description)',
        '| eval description=if(response_code == "", "Connection failed",'
        " description) \n"
        '| eval description=if(timed_out == 1, "Connection timed out", description)',
    )
    alert["search"] = replaced(
        search,
        "| fields - has_expected_string",
        "| fields - has_expected_string timed_out",
    )

    searches["Website Ping Runner Silent"] = dict(RUNNER_SILENT)
    return searches


def test_object_names_are_website_monitorings() -> None:
    """Renaming a stanza would break searches and local/ overrides written for 2.9.7."""
    assert set(read_conf("default/macros.conf")) == MACROS
    assert set(read_conf("default/savedsearches.conf")) == SAVED_SEARCHES
    assert MACROS == set(legacy_conf("macros.conf"))
    assert SAVED_SEARCHES == set(legacy_conf("savedsearches.conf")) - {
        "web_ping_inputs_lookup_gen"
    } | {"Website Ping Runner Silent"}


def test_macros_are_website_monitorings_with_documented_changes() -> None:
    assert read_conf("default/macros.conf") == expected_macros()


def test_saved_searches_are_website_monitorings_with_documented_changes() -> None:
    assert read_conf("default/savedsearches.conf") == expected_saved_searches()


def test_alert_search_text() -> None:
    assert (
        read_conf("default/savedsearches.conf")["Website Performance Problem"]["search"]
        == ALERT_SEARCH
    )


def test_no_shipped_search_relies_on_fillnull_for_response_code() -> None:
    for path in ("default/macros.conf", "default/savedsearches.conf"):
        for name, stanza in read_conf(path).items():
            for key, value in stanza.items():
                assert FILLNULL not in value, f"{path} [{name}] {key}"


def test_runner_silent_alert_reads_the_runner_heartbeat() -> None:
    """The alert finds the heartbeat line in the runner's log file and waits for
    several missed heartbeats before it reports a host."""
    search = read_conf("default/savedsearches.conf")["Website Ping Runner Silent"][
        "search"
    ]
    assert f"source=*{logger.LOG_FILE_NAME}*" in search
    assert " heartbeat " in search
    assert '"-10m"' in search
    assert 10 * 60 >= 5 * wp_runner.HEARTBEAT


def test_legacy_copies_match_the_tag_archive() -> None:
    """The copies under tests/fixtures equal the 2.9.7 tag's files (when the
    archive downloaded for the golden capture is in the cache)."""
    archive = legacy.CACHE / f"splunk-website-monitoring-{legacy.LEGACY_VERSION}.tar.gz"
    if not archive.exists():
        pytest.skip(f"{archive} not downloaded")
    assert legacy.sha256(archive) == legacy.LEGACY_SHA256
    with tarfile.open(archive, "r:gz") as tar:
        members = {
            "/".join(member.name.split("/")[1:]): member
            for member in tar.getmembers()
            if member.isfile()
        }

        def member_text(name: str) -> bytes:
            extracted = tar.extractfile(members[name])
            assert extracted is not None
            return extracted.read()

        for name in ("macros.conf", "savedsearches.conf"):
            assert parse_conf(member_text(f"src/default/{name}").decode("utf-8")) == (
                legacy_conf(name)
            ), name
        lookup = member_text("src/lookups/http_response_codes.csv")
        assert hashlib.sha256(lookup).hexdigest() == LOOKUP_SHA256
