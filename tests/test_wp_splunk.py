"""wp_splunk: website_monitoring.conf and storage/passwords from recorded splunkd
responses (tests/fixtures/splunkd/, captured on Splunk 9.4 with the probe app)."""

from __future__ import annotations

import copy
import json
import logging
import sys
import types
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import cast

import pytest
import wp_splunk
from logger import StanzaLogger, log_to_stderr, setup_logging
from wp_splunk import (
    BUILTIN,
    CONF_PATH,
    PASSWORDS_PATH,
    PROXY_PASSWORD_REFUSED,
    ConfigCache,
    Configuration,
    ProxyConf,
    RestClient,
    SplunkdError,
    build_app_config,
    build_password_store,
)

FIXTURES = Path(__file__).absolute().parent / "fixtures" / "splunkd"
SESSION_KEY = "session-key-must-not-be-logged"
INPUT_PASSWORD = "input-password-must-not-be-logged"
RECORDED_PROXY_PASSWORD = "fixture-proxy-password"

Document = dict[str, object]


def recorded(name: str) -> Document:
    return cast(Document, json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def _entry_list(document: Document) -> list[dict[str, object]]:
    return cast("list[dict[str, object]]", document["entry"])


def conf_document(stanzas: Mapping[str, Mapping[str, str]]) -> Document:
    """The recorded conf list with its entries replaced. Each entry keeps the recorded
    shape (acl, links, disabled, eai:acl); only its text values are the given ones."""
    document = recorded("conf-list.json")
    template = _entry_list(document)[0]
    entries: list[dict[str, object]] = []
    for name, values in stanzas.items():
        entry = copy.deepcopy(template)
        content = cast("dict[str, object]", entry["content"])
        kept = {k: v for k, v in content.items() if not isinstance(v, str)}
        entry["name"] = name
        entry["content"] = {**kept, **values}
        entries.append(entry)
    document["entry"] = entries
    return document


def password_document(*stored: tuple[str, str, str]) -> Document:
    """The recorded passwords list with entries (realm, username, clear_password)
    built from its one recorded entry."""
    document = recorded("passwords.json")
    template = _entry_list(document)[0]
    entries: list[dict[str, object]] = []
    for realm, username, clear in stored:
        entry = copy.deepcopy(template)
        content = cast("dict[str, object]", entry["content"])
        content.update(realm=realm, username=username, clear_password=clear)
        entry["name"] = f"{realm.replace(':', chr(92) + ':')}:{username}:"
        entries.append(entry)
    document["entry"] = entries
    return document


class FakeClient:
    def __init__(self, conf: Document, passwords: Document) -> None:
        self.responses: dict[str, Document] = {
            CONF_PATH: conf,
            PASSWORDS_PATH: passwords,
        }
        self.calls: list[str] = []
        self.error: str | None = None

    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        assert params == {}
        self.calls.append(path)
        if self.error is not None:
            raise SplunkdError(self.error)
        return self.responses[path]


class Clock:
    def __init__(self) -> None:
        self.now: float = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def log_file(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "website_ping.log"
    assert setup_logging(str(path)) is not None
    yield path
    log_to_stderr()


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


# ---- website_monitoring.conf ------------------------------------------------


def test_recorded_conf_reads_default_through_wp_defaults() -> None:
    app, notices = build_app_config(recorded("conf-list.json"))
    assert notices == []
    assert app.thread_limit == 9
    assert app.max_response_body_length == 1000
    default = app.configuration("")
    assert default == Configuration(proxy=ProxyConf(proxy_server="proxy.invalid"))
    assert app.configuration("default") == default
    assert app.configuration("wp_defaults") == default


def test_recorded_named_stanza_holds_default_values() -> None:
    app, _ = build_app_config(recorded("conf-list.json"))
    assert app.configuration("named") == Configuration(
        proxy=ProxyConf(proxy_server="proxy.invalid", proxy_port="3128")
    )
    assert set(app.configurations) == {"default", "named"}


def test_recorded_single_stanza_matches_the_list() -> None:
    single = dict(wp_splunk.entries(recorded("conf-wp_defaults.json")))
    listed = dict(wp_splunk.entries(recorded("conf-list.json")))
    assert single["wp_defaults"] == listed["wp_defaults"]


def test_missing_named_stanza_is_none() -> None:
    app, _ = build_app_config(recorded("conf-list.json"))
    assert app.configuration("no_such_stanza") is None
    assert app.refusal("no_such_stanza") is None


def test_builtin_values_when_nothing_is_set() -> None:
    app, notices = build_app_config(conf_document({"wp_defaults": {}}))
    assert notices == []
    assert app.thread_limit == 200
    assert app.max_response_body_length == 1000
    assert app.configuration("") == BUILTIN
    assert BUILTIN.proxy.proxy_type == "http"
    assert BUILTIN.ssl_verify is False
    assert BUILTIN.ca_certs is None


def test_missing_wp_defaults_warns_and_uses_builtin_values() -> None:
    app, notices = build_app_config(conf_document({"named": {"thread_limit": "5"}}))
    assert [n.level for n in notices] == [logging.WARNING]
    assert "[wp_defaults] is missing" in notices[0].message
    assert app.thread_limit == 200
    assert app.configuration("") == BUILTIN
    assert app.configuration("named") == BUILTIN


def test_empty_response_is_like_missing_wp_defaults() -> None:
    app, notices = build_app_config({"entry": []})
    assert len(notices) == 1
    assert app.configuration("") == BUILTIN


@pytest.mark.parametrize(
    ("raw", "level", "expected"),
    [
        ("many", logging.ERROR, 200),
        ("2.5", logging.ERROR, 200),
        ("0", logging.WARNING, 200),
        ("-3", logging.WARNING, 200),
        (" 50 ", None, 50),
    ],
)
def test_thread_limit(raw: str, level: int | None, expected: int) -> None:
    app, notices = build_app_config(
        conf_document({"wp_defaults": {"thread_limit": raw}})
    )
    assert app.thread_limit == expected
    assert [n.level for n in notices] == ([] if level is None else [level])


@pytest.mark.parametrize(
    ("raw", "errors", "expected"),
    [("lots", 1, 1000), ("-1", 0, -1), ("0", 0, 0), ("250", 0, 250)],
)
def test_max_response_body_length(raw: str, errors: int, expected: int) -> None:
    document = conf_document({"wp_defaults": {"max_response_body_length": raw}})
    app, notices = build_app_config(document)
    assert app.max_response_body_length == expected
    assert [n.level for n in notices] == [logging.ERROR] * errors


def test_limits_come_from_default_only() -> None:
    document = conf_document(
        {
            "wp_defaults": {},
            "named": {"thread_limit": "x", "max_response_body_length": "y"},
        }
    )
    app, notices = build_app_config(document)
    assert (app.thread_limit, app.max_response_body_length) == (200, 1000)
    assert notices == []


def test_ssl_verify_and_ca_certs_from_default_and_per_configuration() -> None:
    document = conf_document(
        {
            # splunkd merges [default] into named stanzas, so named holds it too.
            "wp_defaults": {"ssl_verify": "true", "ca_certs": "/etc/ca.pem"},
            "inherits": {"ssl_verify": "true", "ca_certs": "/etc/ca.pem"},
            "off": {"ssl_verify": "0", "ca_certs": ""},
        }
    )
    app, _ = build_app_config(document)
    assert app.configuration("") == Configuration(
        ssl_verify=True, ca_certs="/etc/ca.pem"
    )
    assert app.configuration("inherits") == app.configuration("")
    assert app.configuration("off") == Configuration(ssl_verify=False, ca_certs=None)


def test_invalid_ssl_verify_refuses_the_configuration() -> None:
    document = conf_document({"wp_defaults": {}, "bad": {"ssl_verify": "yes"}})
    app, _ = build_app_config(document)
    assert app.configuration("bad") is None
    assert app.refusal("bad") == "ssl_verify must be true, false, 1 or 0, got 'yes'"


def test_proxy_settings_are_stripped_text() -> None:
    values = {
        "proxy_type": " socks5 ",
        "proxy_server": "proxy.example",
        "proxy_port": "1080",
        "proxy_user": "bob",
        "proxy_ignore": "*.local",
    }
    app, _ = build_app_config(conf_document({"wp_defaults": {}, "socks": values}))
    assert app.configuration("socks") == Configuration(
        proxy=ProxyConf("socks5", "proxy.example", "1080", "bob", "*.local")
    )


def test_blank_proxy_type_is_http() -> None:
    app, _ = build_app_config(conf_document({"wp_defaults": {"proxy_type": " "}}))
    assert app.configuration("") == BUILTIN


def test_plain_proxy_password_refuses_the_configuration() -> None:
    secret = "plain-proxy-password"
    document = conf_document(
        {
            "wp_defaults": {"proxy_password": " "},
            "plain": {"proxy_server": "p", "proxy_password": secret},
        }
    )
    app, notices = build_app_config(document)
    assert app.configuration("") == BUILTIN
    assert app.configuration("plain") is None
    assert app.refusal("plain") == PROXY_PASSWORD_REFUSED
    assert secret not in repr(app)
    assert all(secret not in n.message for n in notices)


def test_plain_proxy_password_in_default_refuses_every_configuration() -> None:
    values = {"proxy_server": "p", "proxy_password": "x"}
    document = conf_document({"wp_defaults": values, "named": values})
    app, _ = build_app_config(document)
    assert app.configurations == {}
    assert set(app.refused) == {"default", "named"}
    assert app.refusal("") == PROXY_PASSWORD_REFUSED


# ---- storage/passwords ------------------------------------------------------


def test_recorded_proxy_password() -> None:
    store = build_password_store(recorded("passwords.json"))
    assert len(store) == 1
    assert store.proxy_password() == RECORDED_PROXY_PASSWORD
    assert store.input_password("web_ping://site_a") is None


def test_input_password_by_realm_first_match_any_user() -> None:
    store = build_password_store(
        password_document(
            ("postgres", "es.root", "system-secret"),
            ("web_ping://site_a", "alice", "first"),
            ("web_ping://site_a", "bob", "second"),
        )
    )
    assert store.input_password("web_ping://site_a") == "first"


@pytest.mark.parametrize(
    "stanza", ["web_ping://site", "web_ping://site_ab", "WEB_PING://site_a", "site_a"]
)
def test_input_password_realm_must_match_exactly(stanza: str) -> None:
    store = build_password_store(password_document(("web_ping://site_a", "u", "pw")))
    assert store.input_password(stanza) is None


def test_proxy_password_needs_realm_and_user() -> None:
    store = build_password_store(
        password_document(
            ("website_monitoring_app_proxy", "someone", "wrong-user"),
            ("other_realm", "IN_CONF_FILE", "wrong-realm"),
        )
    )
    assert store.proxy_password() is None


def test_incomplete_entries_are_skipped() -> None:
    document = password_document(
        ("web_ping://a", "u", "pw"), ("web_ping://b", "u", "pw")
    )
    entries = _entry_list(document)
    del cast("dict[str, object]", entries[0]["content"])["clear_password"]
    entries.append({"name": "no content"})
    store = build_password_store(document)
    assert len(store) == 1
    assert store.input_password("web_ping://a") is None
    assert store.input_password("web_ping://b") == "pw"


def test_password_store_repr_shows_counts_only() -> None:
    store = build_password_store(password_document(("r", "u", INPUT_PASSWORD)))
    assert repr(store) == "PasswordStore(entries=1)"
    assert INPUT_PASSWORD not in repr(
        wp_splunk.StoredPassword("r", "u", INPUT_PASSWORD)
    )


# ---- RestClient -------------------------------------------------------------


class Response:
    def __init__(self, status: int) -> None:
        self.status: int = status


def install_splunk_rest(
    monkeypatch: pytest.MonkeyPatch, simple_request: object
) -> None:
    package = types.ModuleType("splunk")
    module = types.ModuleType("splunk.rest")
    module.simpleRequest = simple_request  # type: ignore[attr-defined]
    package.rest = module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "splunk", package)
    monkeypatch.setitem(sys.modules, "splunk.rest", module)


def returning(result: tuple[object, object]) -> Callable[..., tuple[object, object]]:
    def simple_request(*_args: object, **_kwargs: object) -> tuple[object, object]:
        return result

    return simple_request


def test_rest_client_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, Mapping[str, str]]] = []
    body = json.dumps(recorded("conf-list.json")).encode("utf-8")

    def simple_request(
        path: str, *, sessionKey: str, getargs: Mapping[str, str]
    ) -> tuple[object, object]:
        calls.append((path, sessionKey, getargs))
        return Response(200), body

    install_splunk_rest(monkeypatch, simple_request)
    document = RestClient(SESSION_KEY).get_json(CONF_PATH, {"search": "x"})
    assert calls == [
        (CONF_PATH, SESSION_KEY, {"search": "x", "output_mode": "json", "count": "0"})
    ]
    assert document == recorded("conf-list.json")


def test_rest_client_accepts_a_status_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    install_splunk_rest(monkeypatch, returning(({"status": "200"}, "{}")))
    assert RestClient(SESSION_KEY).get_json(CONF_PATH, {}) == {}


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ((Response(500), b"{}"), "returned status 500"),
        ((Response(200), b"<html>"), "returned no JSON"),
        ((Response(200), b"[]"), "not an object"),
    ],
)
def test_rest_client_bad_responses(
    monkeypatch: pytest.MonkeyPatch, result: tuple[object, object], message: str
) -> None:
    install_splunk_rest(monkeypatch, returning(result))
    with pytest.raises(SplunkdError, match=message):
        _ = RestClient(SESSION_KEY).get_json(PASSWORDS_PATH, {})


def test_rest_client_wraps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> tuple[object, object]:
        raise ConnectionRefusedError(111, "Connection refused")

    install_splunk_rest(monkeypatch, refuse)
    with pytest.raises(SplunkdError) as caught:
        _ = RestClient(SESSION_KEY).get_json(CONF_PATH, {})
    assert str(caught.value).startswith(
        f"GET {CONF_PATH} failed: ConnectionRefusedError"
    )
    assert caught.value.__cause__ is None
    assert SESSION_KEY not in str(caught.value)


def test_rest_client_without_splunk_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "splunk", None)
    with pytest.raises(SplunkdError, match="splunk.rest is not available"):
        _ = RestClient(SESSION_KEY).get_json(CONF_PATH, {})


def test_rest_client_repr_hides_the_session_key() -> None:
    assert SESSION_KEY not in repr(RestClient(SESSION_KEY))


# ---- ConfigCache ------------------------------------------------------------


def make_cache(
    clock: Clock, logger: StanzaLogger | None = None
) -> tuple[ConfigCache, FakeClient]:
    client = FakeClient(
        recorded("conf-list.json"),
        password_document(("web_ping://site_a", "alice", INPUT_PASSWORD)),
    )
    cache = ConfigCache(client, clock=clock, logger=logger or StanzaLogger(None))
    return cache, client


def test_cache_loads_once_then_after_ten_minutes() -> None:
    clock = Clock()
    cache, client = make_cache(clock)
    assert cache.snapshot is None
    first = cache.refresh_if_due()
    assert first is not None and first.generation == 1
    assert first.app.thread_limit == 9
    assert first.passwords.input_password("web_ping://site_a") == INPUT_PASSWORD
    assert client.calls == [CONF_PATH, PASSWORDS_PATH]
    clock.now += 599
    assert cache.refresh_if_due() is first
    assert len(client.calls) == 2
    clock.now += 1
    second = cache.refresh_if_due()
    assert second is not None and second.generation == 2
    assert len(client.calls) == 4
    assert cache.snapshot is second


def test_cache_refresh_failure_keeps_values_and_warns_once(log_file: Path) -> None:
    clock = Clock()
    cache, client = make_cache(clock)
    first = cache.refresh_if_due()
    client.error = "GET x failed: SplunkdConnectionException: down"
    for _ in range(3):
        clock.now += 600
        assert cache.refresh_if_due() is first
    warnings = [line for line in lines(log_file) if " WARN " in line]
    assert len(warnings) == 1
    assert "cannot refresh configuration from splunkd" in warnings[0]
    assert "SplunkdConnectionException: down" in warnings[0]
    client.error = None
    clock.now += 30
    recovered = cache.refresh_if_due()
    assert recovered is not None and recovered.generation == 2
    assert any("after 3 failed attempts" in line for line in lines(log_file))


def test_cache_retries_a_failed_refresh_after_thirty_seconds() -> None:
    clock = Clock()
    cache, client = make_cache(clock)
    _ = cache.refresh_if_due()
    client.error = "down"
    clock.now += 600
    _ = cache.refresh_if_due()
    calls = len(client.calls)
    clock.now += 29
    _ = cache.refresh_if_due()
    assert len(client.calls) == calls
    clock.now += 1
    _ = cache.refresh_if_due()
    assert len(client.calls) == calls + 1


def test_cache_initial_failure_runs_nothing_and_retries(log_file: Path) -> None:
    clock = Clock()
    cache, client = make_cache(clock)
    client.error = "GET x failed: SplunkdConnectionException: down"
    assert cache.refresh_if_due() is None
    clock.now += 29
    assert cache.refresh_if_due() is None
    assert len(client.calls) == 1
    clock.now += 1
    assert cache.refresh_if_due() is None
    assert len(client.calls) == 2
    errors = [line for line in lines(log_file) if " ERROR " in line]
    assert len(errors) == 1
    assert "no checks run until it succeeds" in errors[0]
    client.error = None
    clock.now += 30
    snapshot = cache.refresh_if_due()
    assert snapshot is not None and snapshot.generation == 1


def test_cache_failed_password_read_fails_the_whole_load() -> None:
    clock = Clock()
    cache, client = make_cache(clock)

    def conf_only(path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        client.calls.append(path)
        if path == PASSWORDS_PATH:
            raise SplunkdError("GET passwords failed")
        return client.responses[path]

    client.get_json = conf_only  # type: ignore[method-assign]
    assert cache.refresh_if_due() is None


def test_cache_logs_conf_notices_on_each_load(log_file: Path) -> None:
    clock = Clock()
    cache, client = make_cache(clock)
    client.responses[CONF_PATH] = conf_document({"wp_defaults": {"thread_limit": "x"}})
    _ = cache.refresh_if_due()
    clock.now += 600
    _ = cache.refresh_if_due()
    errors = [line for line in lines(log_file) if " ERROR " in line]
    assert len(errors) == 2
    assert all("website_monitoring.conf: thread_limit must be" in e for e in errors)


def test_no_secret_reaches_the_log_or_stderr(
    log_file: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every path of the cache at DEBUG: load, refresh, failures, recovery, refused
    plain proxy password, and RestClient errors."""
    plain = "plain-proxy-password-in-conf"
    clock = Clock()
    cache, client = make_cache(clock, StanzaLogger(None, logging.DEBUG))
    client.responses[CONF_PATH] = conf_document(
        {"wp_defaults": {}, "plain": {"proxy_password": plain}}
    )
    client.responses[PASSWORDS_PATH] = password_document(
        ("web_ping://site_a", "alice", INPUT_PASSWORD),
        ("website_monitoring_app_proxy", "IN_CONF_FILE", RECORDED_PROXY_PASSWORD),
    )
    snapshot = cache.refresh_if_due()
    assert snapshot is not None
    client.error = "down"
    for _ in range(2):
        clock.now += 600
        _ = cache.refresh_if_due()
    client.error = None
    clock.now += 30
    _ = cache.refresh_if_due()

    def refuse(*_args: object, **_kwargs: object) -> tuple[object, object]:
        raise RuntimeError("splunkd said no")

    install_splunk_rest(monkeypatch, refuse)
    rest_cache = ConfigCache(
        RestClient(SESSION_KEY), clock=clock, logger=StanzaLogger(None, logging.DEBUG)
    )
    assert rest_cache.refresh_if_due() is None

    output = "\n".join(
        [
            log_file.read_text(encoding="utf-8"),
            capsys.readouterr().err,
            repr(snapshot),
            repr(rest_cache.snapshot),
        ]
    )
    assert "configuration loaded generation=1" in output
    for secret in (INPUT_PASSWORD, RECORDED_PROXY_PASSWORD, plain, SESSION_KEY):
        assert secret not in output
