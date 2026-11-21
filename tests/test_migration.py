"""The configuration to migrate and the file rules read from docs/migration.md
(wptest/migration.py)."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

import pytest
from ping_config import ConfigError, build_settings
from target import server
from wptest import legacy, migration
from wptest.conf import parse_conf
from wptest.install import ROOT
from wptest.migration import CopyRule, FileRules, LegacyInput
from wptest.parity import PROXY_REALM, PROXY_USERNAME
from wptest.stack import PROXY_PASSWORD

GOLDEN_DIR = ROOT / "tests" / "golden" / legacy.LEGACY_VERSION


# ---- inputs -----------------------------------------------------------------


def test_titles_are_unique() -> None:
    titles = [i.title for i in migration.LEGACY_INPUTS]
    assert len(titles) == len(set(titles))


def test_intervals_cover_quick_and_production_schedules() -> None:
    seconds = {i.seconds for i in migration.LEGACY_INPUTS}
    assert {60, 300, 600, 900, 3600} <= seconds
    assert all(i.interval.endswith(("m", "h")) for i in migration.LEGACY_INPUTS)


@pytest.mark.parametrize(
    ("interval", "seconds"), [("45", 45), ("30s", 30), ("10m", 600), ("2h", 7200)]
)
def test_interval_seconds(interval: str, seconds: int) -> None:
    item = LegacyInput(migration.URL_CREDENTIALS, interval)
    assert item.seconds == seconds


def test_every_input_but_the_url_credentials_has_a_golden_fixture() -> None:
    without = [
        i.title
        for i in migration.LEGACY_INPUTS
        if not (GOLDEN_DIR / f"{i.title}.json").exists()
    ]
    assert without == [migration.URL_CREDENTIALS.title]


def test_one_input_lives_in_the_search_app() -> None:
    assert [i.title for i in migration.inputs_in(migration.SEARCH_APP)] == [
        "status-404"
    ]


def test_inputs_conf_holds_the_old_apps_inputs_in_order() -> None:
    for changed in (False, True):
        conf = parse_conf(migration.inputs_conf(changed=changed))
        assert list(conf) == [
            i.stanza for i in migration.inputs_in(migration.LEGACY_APP)
        ]


def test_plain_secrets_before_the_changes() -> None:
    conf = parse_conf(migration.inputs_conf(changed=False))
    assert conf["web_ping://basic-plain"]["password"] == server.AUTH_PASSWORD
    url = urlsplit(conf["web_ping://url-credentials"]["url"])
    assert (url.username, url.password) == (server.AUTH_USER, server.AUTH_PASSWORD)
    assert "username" not in conf["web_ping://url-credentials"]
    proxies = parse_conf(migration.website_monitoring_conf(changed=False))
    assert proxies["auth"]["proxy_password"] == PROXY_PASSWORD


def test_no_plain_secret_after_the_changes() -> None:
    files = migration.legacy_files(changed=True)
    for secret in migration.PLAIN_SECRETS:
        assert not [name for name, text in files.items() if secret in text]


def test_changes_move_the_url_user_into_username() -> None:
    conf = parse_conf(migration.inputs_conf(changed=True))
    stanza = conf["web_ping://url-credentials"]
    assert (
        stanza["url"] == f"http://target:{server.HTTP_PORT}/auth/basic/url-credentials"
    )
    assert stanza["username"] == server.AUTH_USER


def test_changes_touch_only_the_secrets() -> None:
    for item in migration.LEGACY_INPUTS:
        before = item.settings(changed=False)
        after = item.settings(changed=True)
        changed = {
            k for k in before.keys() | after.keys() if before.get(k) != after.get(k)
        }
        assert changed <= {"password", "url", "username"}, item.title


@pytest.mark.parametrize("item", migration.LEGACY_INPUTS, ids=lambda i: i.title)
def test_website_ping_accepts_every_changed_stanza(item: LegacyInput) -> None:
    _ = build_settings(item.stanza, item.settings(changed=True))


@pytest.mark.parametrize("title", ["basic-plain", "url-credentials"])
def test_website_ping_refuses_the_plain_secrets(title: str) -> None:
    item = next(i for i in migration.LEGACY_INPUTS if i.title == title)
    with pytest.raises(ConfigError):
        _ = build_settings(item.stanza, item.settings(changed=False))


def test_without_userinfo() -> None:
    assert migration.without_userinfo("https://u:p@h:1/a@b?c") == "https://h:1/a@b?c"
    assert migration.without_userinfo("http://h/x") == "http://h/x"


# ---- website_monitoring.conf and passwords ---------------------------------


def test_website_monitoring_conf_stanzas() -> None:
    conf = parse_conf(migration.website_monitoring_conf(changed=True))
    assert list(conf) == ["default", "plain", "auth", "ignore"]
    assert conf["default"] == {"thread_limit": "20", "max_response_body_length": "1000"}
    assert "proxy_password" not in conf["auth"]


def test_every_configuration_an_input_names_exists() -> None:
    conf = parse_conf(migration.website_monitoring_conf(changed=True))
    named = {
        i.scenario.conf for i in migration.LEGACY_INPUTS if i.scenario.conf is not None
    }
    assert named <= set(conf)


def test_stored_passwords_cover_every_removed_secret() -> None:
    realms = {(p.realm, p.username) for p in migration.MOVED_TO_STORE}
    assert realms == {
        ("web_ping://basic-plain", server.AUTH_USER),
        ("web_ping://url-credentials", server.AUTH_USER),
        (PROXY_REALM, PROXY_USERNAME),
    }
    assert {p.app for p in migration.MOVED_TO_STORE} == {migration.SEARCH_APP}
    assert [p.app for p in migration.PRESTORED] == [migration.LEGACY_APP]


def test_a_new_host_stores_every_password_in_search() -> None:
    entries = migration.NEW_HOST_PASSWORDS
    assert {p.app for p in entries} == {migration.SEARCH_APP}
    assert {p.realm for p in entries} == {
        p.realm for p in (*migration.PRESTORED, *migration.MOVED_TO_STORE)
    }


def test_static_and_generated_files() -> None:
    files = migration.legacy_files(changed=True)
    assert sorted(files) == [
        "local/app.conf",
        "local/eventtypes.conf",
        "local/inputs.conf",
        "local/macros.conf",
        "local/savedsearches.conf",
        "local/website_monitoring.conf",
    ]
    for name, text in files.items():
        assert parse_conf(text), name


def test_overrides_in_the_static_files() -> None:
    files = migration.static_files()
    macros = parse_conf(files["local/macros.conf"])
    assert macros["response_time_threshold"]["definition"] == "250"
    assert macros["website_monitoring_search_index"]["definition"] == "index=main"
    eventtypes = parse_conf(files["local/eventtypes.conf"])
    assert (
        eventtypes["filter_website_monitoring_alerts"]["search"] == 'title="status-503"'
    )
    searches = parse_conf(files["local/savedsearches.conf"])
    user_search = searches["Failed checks today"]["search"]
    assert "`format_events_ex`" in user_search
    assert "`filter_inoperable`" in user_search


# ---- the guide's file tables ------------------------------------------------


def test_the_guide_has_readable_file_tables() -> None:
    rules = migration.read_file_rules()
    copies = {rule.pattern: rule for rule in rules.copy}
    for name in (
        "local/inputs.conf",
        "local/website_monitoring.conf",
        "local/passwords.conf",
        "local/macros.conf",
        "local/eventtypes.conf",
        "local/tags.conf",
        "local/savedsearches.conf",
    ):
        assert copies[name] == CopyRule(name, merge=False)
    assert copies["metadata/local.meta"].merge
    assert copies["lookups/*.csv"].skip == (
        "http_response_codes.csv",
        "web_ping_inputs.csv",
    )
    assert "local/app.conf" in rules.keep_out
    assert "local/data/ui/nav/" in rules.keep_out
    assert "local/data/ui/views/adhoc_web_ping.xml" in rules.keep_out


def test_plan_for_the_legacy_app() -> None:
    files = [
        *migration.legacy_files(changed=True),
        "local/passwords.conf",
        "default/app.conf",
        "default/inputs.conf",
        "lookups/http_response_codes.csv",
        "lookups/my_sites.csv",
        "metadata/default.meta",
        "metadata/local.meta",
        "bin/web_ping.py",
    ]
    plan = migration.plan_copies(files, migration.read_file_rules())
    assert plan.copy == (
        "local/eventtypes.conf",
        "local/inputs.conf",
        "local/macros.conf",
        "local/passwords.conf",
        "local/savedsearches.conf",
        "local/website_monitoring.conf",
        "lookups/my_sites.csv",
    )
    assert plan.merge == ("metadata/local.meta",)
    assert "local/app.conf" in plan.left
    assert "lookups/http_response_codes.csv" in plan.left


def test_a_file_both_copied_and_kept_out_is_an_error() -> None:
    rules = FileRules((CopyRule("local/*.conf", merge=False),), ("local/app.conf",))
    with pytest.raises(ValueError, match="local/app.conf"):
        _ = migration.plan_copies(["local/app.conf"], rules)


def test_patterns_do_not_cross_folders() -> None:
    assert migration.matches("local/*.conf", "local/a.conf")
    assert not migration.matches("local/*.conf", "local/data/a.conf")
    assert migration.matches("local/data/ui/nav/", "local/data/ui/nav/default.xml")


GUIDE = """\
# Guide

## Files to copy

| File | What to do |
| --- | --- |
| `local/a.conf`, `local/b.conf` | Copy to `local/`. |
| `lookups/*.csv` you added | Copy. Skip `x.csv` and `notes.txt`. |
| `metadata/local.meta` | Merge its stanzas. |

Do not copy:

| File | Why |
| --- | --- |
| `local/app.conf` | No. |
| Views `one`, `two` | Gone. |

## Steps
"""


def test_file_rules_from_a_small_guide() -> None:
    assert migration.file_rules(GUIDE) == FileRules(
        (
            CopyRule("local/a.conf", merge=False),
            CopyRule("local/b.conf", merge=False),
            CopyRule("lookups/*.csv", merge=False, skip=("x.csv",)),
            CopyRule("metadata/local.meta", merge=True),
        ),
        (
            "local/app.conf",
            "local/data/ui/views/one.xml",
            "local/data/ui/views/two.xml",
        ),
    )


def test_an_unreadable_row_is_an_error() -> None:
    broken = GUIDE.replace("| `local/app.conf` | No. |", "| app.conf | No. |")
    with pytest.raises(ValueError, match="app.conf"):
        _ = migration.file_rules(broken)


def test_a_missing_table_is_an_error() -> None:
    with pytest.raises(ValueError, match="What to do"):
        _ = migration.file_rules(GUIDE.replace("What to do", "Action"))


# ---- metadata ---------------------------------------------------------------


def test_merge_meta_keeps_existing_stanzas_and_adds_new_ones() -> None:
    existing = "[app/install/install_source_checksum]\nversion = 1.0.0\n"
    old = (
        "[app/install/install_source_checksum]\nversion = 9.4.17\n\n"
        "[savedsearches/Failed%20checks%20today]\nowner = admin\n"
    )
    merged = migration.merge_meta(existing, old)
    assert parse_conf(merged) == {
        "app/install/install_source_checksum": {"version": "1.0.0"},
        "savedsearches/Failed%20checks%20today": {"owner": "admin"},
    }


def test_merge_meta_without_an_existing_file() -> None:
    old = "[views/a]\nexport = system\n"
    assert migration.merge_meta(None, old) == old


def test_stanza_blocks_skip_leading_comments() -> None:
    assert migration.stanza_blocks("# c\n\n[a]\nx = 1\n\n[b]\n") == [
        ("a", "[a]\nx = 1\n"),
        ("b", "[b]\n"),
    ]


# ---- the guide's commands and searches --------------------------------------


def guide() -> str:
    return migration.GUIDE.read_text(encoding="utf-8")


def test_standalone_steps_stop_move_unpack_then_start() -> None:
    before_copy, start = migration.standalone_steps(guide())
    lines = before_copy.splitlines()
    assert lines[0].endswith("bin/splunk stop")
    assert any(
        line.startswith("mv ") and "website_monitoring" in line for line in lines
    )
    assert any(migration.PACKAGE_PLACEHOLDER in line for line in lines)
    assert start.strip().endswith("bin/splunk start")


def test_rollback_steps_and_keys() -> None:
    steps = migration.rollback_steps(guide()).splitlines()
    assert steps[0].endswith("bin/splunk stop")
    assert steps[-1].endswith("bin/splunk start")
    assert migration.rollback_keys(guide()) == (
        "ssl_verify",
        "ca_certs",
        "log_level",
        "python.required",
    )


def test_after_start_searches() -> None:
    problems, arriving = migration.after_start_searches(guide())
    assert "website_ping:log" in problems
    assert arriving.startswith("sourcetype=web_ping")


def test_unattended_fills_the_package_and_answers_prompts() -> None:
    script = "$SPLUNK_HOME/bin/splunk stop\ntar -xzf website_ping-<version>.tar.gz\n"
    assert migration.unattended(script, "website_ping-1.2.3.tar.gz") == (
        "set -e\n$SPLUNK_HOME/bin/splunk stop\ntar -xzf website_ping-1.2.3.tar.gz\n"
    )
    assert migration.unattended("$SPLUNK_HOME/bin/splunk start\n") == (
        "set -e\n$SPLUNK_HOME/bin/splunk start --answer-yes --no-prompt\n"
    )
    with pytest.raises(ValueError, match="version"):
        _ = migration.unattended("echo\n", "website_ping-1.2.3.tar.gz")


def test_without_old_app_keeps_stop_and_unpack() -> None:
    before_copy, _ = migration.standalone_steps(guide())
    lines = migration.without_old_app(before_copy).splitlines()
    assert lines[0].endswith("bin/splunk stop")
    assert lines[-1].startswith("tar -xzf ")
    assert not [line for line in lines if migration.LEGACY_APP in line]
    with pytest.raises(ValueError, match=migration.LEGACY_APP):
        _ = migration.without_old_app("echo\n")


def test_remove_keys_only_in_web_ping_stanzas() -> None:
    text = (
        "[web_ping]\nssl_verify = true\nuser_agent = x\n\n"
        "[web_ping://a]\nlog_level = DEBUG\nurl = http://a/\n\n"
        "[other]\nlog_level = DEBUG\n"
    )
    assert migration.remove_keys(text, ("ssl_verify", "log_level")) == (
        "[web_ping]\nuser_agent = x\n\n"
        "[web_ping://a]\nurl = http://a/\n\n"
        "[other]\nlog_level = DEBUG\n"
    )


def test_files_setting_reads_btool_debug_output() -> None:
    output = (
        "/opt/splunk/etc/apps/search/local/inputs.conf  [web_ping://a]\n"
        "/opt/splunk/etc/apps/search/local/inputs.conf  log_level = DEBUG\n"
        "/opt/splunk/etc/apps/x/default/inputs.conf     url = http://a/\n"
        "/opt/splunk/etc/apps/y/local/inputs.conf       python.required = 3.9\n"
    )
    assert migration.files_setting(output, ("log_level", "python.required")) == [
        "/opt/splunk/etc/apps/search/local/inputs.conf",
        "/opt/splunk/etc/apps/y/local/inputs.conf",
    ]


# ---- checkpoints ------------------------------------------------------------


def test_checkpoint_name_is_the_sha224_of_the_stanza() -> None:
    assert migration.checkpoint_name("web_ping://a") == (
        hashlib.sha224(b"web_ping://a").hexdigest() + ".json"
    )


def test_first_run_window() -> None:
    assert migration.first_run_window(1000.0, 600, 1200.0, 30.0) == (1600.0, 1630.0)
    assert migration.first_run_window(1000.0, 60, 1200.0, 30.0) == (1200.0, 1230.0)
