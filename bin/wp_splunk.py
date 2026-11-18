"""website_monitoring.conf and stored passwords, read from splunkd.

Website Monitoring 2.9.7 read both through splunkd's REST API with the session key
splunkd passes on stdin; so does this module. SplunkdClient is the only part that
talks to splunkd, so the unit tests replace it with recorded responses.

Secrets: the passwords response holds every credential the session key can read,
Splunk's own included. Entries are selected strictly by realm, kept in memory only,
and never logged; neither is the session key.
"""

from __future__ import annotations

import importlib
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from logger import StanzaLogger, process_log
from ping_config import (
    DEFAULT_CONFIGURATION,
    DEFAULT_SSL_VERIFY,
    ConfigError,
    parse_bool,
)

CONF_PATH = "/servicesNS/nobody/website_ping/configs/conf-website_monitoring"
"""All stanzas of website_monitoring.conf as the website_ping app sees them: its own
default/ and local/, plus files of other apps that export them."""
PASSWORDS_PATH = "/services/storage/passwords"
"""Every entry the session key can read, in any app, as Website Monitoring read them.
Entries shared only within another app (for example search) are found as well."""
DEFAULTS_STANZA = "wp_defaults"
"""An empty stanza shipped in default/website_monitoring.conf. splunkd does not list
[default] as an entry but merges it into every stanza, so this one carries exactly
the merged [default] values."""
PROXY_REALM = "website_monitoring_app_proxy"
PROXY_USERNAME = "IN_CONF_FILE"

DEFAULT_THREAD_LIMIT = 200
DEFAULT_MAX_RESPONSE_BODY_LENGTH = 1000
REFRESH_SECONDS = 600.0
"""Website Monitoring cached each configuration for 10 minutes."""
RETRY_SECONDS = 30.0
"""Until the first load succeeds, no check runs; it is retried this often."""
MAX_ERROR_LENGTH = 200
SOCKS_PROXY_TYPES = frozenset({"socks4", "socks5"})
SOCKS_REFUSED = "proxy_type = {proxy_type} is not supported, only HTTP proxies are"
PROXY_PASSWORD_REFUSED = (
    "proxy_password in website_monitoring.conf is not supported; store it in"
    f" storage/passwords, realm {PROXY_REALM}, user {PROXY_USERNAME}"
)


class SplunkdError(Exception):
    """splunkd could not be asked or gave no usable answer. The message names the
    path and the error, never the session key or a response body."""


class SplunkdClient(Protocol):
    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        """GET path with params plus output_mode=json and count=0; the parsed body."""
        ...


class SimpleRequest(Protocol):
    def __call__(
        self, path: str, *, sessionKey: str, getargs: Mapping[str, str]
    ) -> tuple[object, object]: ...


class RestClient:
    """SplunkdClient over splunk.rest.simpleRequest, Splunk's own helper, which knows
    the management port and its certificate settings."""

    def __init__(self, session_key: str) -> None:
        self._session_key: str = session_key

    def __repr__(self) -> str:
        return "RestClient(session_key=<hidden>)"

    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        simple_request = _simple_request()
        getargs = {**params, "output_mode": "json", "count": "0"}
        try:
            response, content = simple_request(
                path, sessionKey=self._session_key, getargs=getargs
            )
        except Exception as exc:  # noqa: BLE001 - splunk.rest raises many types
            raise SplunkdError(f"GET {path} failed: {_describe(exc)}") from None
        status = _status(response)
        if status != 200:
            raise SplunkdError(f"GET {path} returned status {status}")
        return parse_document(path, content)


def _simple_request() -> SimpleRequest:
    """Imported on first use: the splunk package exists only inside Splunk."""
    try:
        module = importlib.import_module("splunk.rest")
    except ImportError as exc:
        raise SplunkdError(f"splunk.rest is not available: {exc}") from None
    return cast(SimpleRequest, module.simpleRequest)


def _status(response: object) -> int | None:
    status = getattr(response, "status", None)
    if status is None and isinstance(response, Mapping):
        status = cast("Mapping[str, object]", response).get("status")
    try:
        return int(str(status))
    except ValueError:
        return None


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]


def parse_document(path: str, content: object) -> Mapping[str, object]:
    """The JSON object of a response body (bytes or text)."""
    try:
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        document: object = json.loads(text)
    except ValueError:
        raise SplunkdError(f"GET {path} returned no JSON") from None
    if not isinstance(document, dict):
        raise SplunkdError(f"GET {path} returned JSON that is not an object")
    return cast("dict[str, object]", document)


def entries(document: Mapping[str, object]) -> list[tuple[str, Mapping[str, str]]]:
    """(name, text values of content) per entry. Values that are not text, such as
    disabled or eai:acl, are dropped."""
    raw = document.get("entry")
    if not isinstance(raw, list):
        return []
    result: list[tuple[str, Mapping[str, str]]] = []
    for item in cast("list[object]", raw):
        if not isinstance(item, dict):
            continue
        entry = cast("dict[str, object]", item)
        name = entry.get("name")
        content = entry.get("content")
        if not isinstance(name, str) or not isinstance(content, dict):
            continue
        values = {
            key: value
            for key, value in cast("dict[str, object]", content).items()
            if isinstance(value, str)
        }
        result.append((name, values))
    return result


# ---- website_monitoring.conf ------------------------------------------------


@dataclass(frozen=True)
class ProxyConf:
    """The proxy settings of one configuration. Empty text means unset."""

    proxy_type: str = "http"
    proxy_server: str = ""
    proxy_port: str = ""
    proxy_user: str = ""
    proxy_ignore: str = ""


@dataclass(frozen=True)
class Configuration:
    """One stanza of website_monitoring.conf, as an input selects it with
    configuration = <name>."""

    proxy: ProxyConf = field(default_factory=ProxyConf)
    ssl_verify: bool = DEFAULT_SSL_VERIFY
    """For inputs that leave ssl_verify blank."""
    ca_certs: str | None = None
    """For inputs that leave ca_certs blank."""


BUILTIN = Configuration()
"""Website Monitoring's built-in values, used for a configuration that does not
exist: no proxy."""


@dataclass(frozen=True)
class Notice:
    """A message about the configuration for the caller to log."""

    level: int
    message: str


@dataclass(frozen=True)
class AppConfig:
    thread_limit: int
    max_response_body_length: int
    configurations: Mapping[str, Configuration]
    """By stanza name; "default" is [default] (read through wp_defaults)."""
    refused: Mapping[str, str]
    """Configurations that cannot be used, by stanza name, with the reason. Inputs
    that select one are not run."""

    def configuration(self, name: str) -> Configuration | None:
        """The configuration an input selects; blank means default. None if the
        stanza does not exist or is refused."""
        return self.configurations.get(_key(name))

    def refusal(self, name: str) -> str | None:
        return self.refused.get(_key(name))


def _key(name: str) -> str:
    stripped = name.strip()
    if stripped in ("", DEFAULT_CONFIGURATION, DEFAULTS_STANZA):
        return DEFAULT_CONFIGURATION
    return stripped


def _text(values: Mapping[str, str], key: str) -> str:
    return values.get(key, "").strip()


def _proxy(values: Mapping[str, str]) -> ProxyConf:
    """Raises ConfigError for a proxy that cannot be used. A check sent directly
    instead would report the site as down when only the proxy setting is wrong."""
    proxy = ProxyConf(
        proxy_type=_text(values, "proxy_type") or "http",
        proxy_server=_text(values, "proxy_server"),
        proxy_port=_text(values, "proxy_port"),
        proxy_user=_text(values, "proxy_user"),
        proxy_ignore=_text(values, "proxy_ignore"),
    )
    if not proxy.proxy_server:
        return proxy
    if proxy.proxy_type.lower() in SOCKS_PROXY_TYPES:
        raise ConfigError(SOCKS_REFUSED.format(proxy_type=proxy.proxy_type))
    port = proxy.proxy_port
    if port and not (port.isascii() and port.isdigit() and 0 < int(port) < 65536):
        raise ConfigError(f"proxy_port must be a number from 1 to 65535, got {port!r}")
    return proxy


def _configuration(values: Mapping[str, str]) -> Configuration:
    """Raises ConfigError for a value that makes the stanza unusable."""
    if _text(values, "proxy_password"):
        raise ConfigError(PROXY_PASSWORD_REFUSED)
    proxy = _proxy(values)
    verify = parse_bool("ssl_verify", values.get("ssl_verify", ""))
    return Configuration(
        proxy=proxy,
        ssl_verify=DEFAULT_SSL_VERIFY if verify is None else verify,
        ca_certs=_text(values, "ca_certs") or None,
    )


def _thread_limit(values: Mapping[str, str], notices: list[Notice]) -> int:
    raw = values.get("thread_limit", "")
    if not raw.strip():
        return DEFAULT_THREAD_LIMIT
    try:
        value = int(raw.strip())
    except ValueError:
        notices.append(
            Notice(
                logging.ERROR,
                f"thread_limit must be an integer, got {raw!r}; using {DEFAULT_THREAD_LIMIT}",
            )
        )
        return DEFAULT_THREAD_LIMIT
    if value <= 0:
        notices.append(
            Notice(
                logging.WARNING,
                f"thread_limit must be greater than 0, got {value}; using {DEFAULT_THREAD_LIMIT}",
            )
        )
        return DEFAULT_THREAD_LIMIT
    return value


def _body_length(values: Mapping[str, str], notices: list[Notice]) -> int:
    raw = values.get("max_response_body_length", "")
    if not raw.strip():
        return DEFAULT_MAX_RESPONSE_BODY_LENGTH
    try:
        return int(raw.strip())
    except ValueError:
        notices.append(
            Notice(
                logging.ERROR,
                f"max_response_body_length must be an integer, got {raw!r};"
                f" using {DEFAULT_MAX_RESPONSE_BODY_LENGTH}",
            )
        )
        return DEFAULT_MAX_RESPONSE_BODY_LENGTH


def build_app_config(
    document: Mapping[str, object],
) -> tuple[AppConfig, list[Notice]]:
    """AppConfig from the conf-website_monitoring response, plus notices to log.

    thread_limit and max_response_body_length come from [default] only, as in
    Website Monitoring. Every named stanza already holds [default]'s values for the
    keys it does not set itself.
    """
    stanzas = dict(entries(document))
    notices: list[Notice] = []
    if DEFAULTS_STANZA not in stanzas:
        notices.append(
            Notice(
                logging.WARNING,
                f"stanza [{DEFAULTS_STANZA}] is missing from website_monitoring.conf,"
                " so [default] cannot be read; using the built-in values",
            )
        )
    defaults: Mapping[str, str] = stanzas.pop(DEFAULTS_STANZA, {})
    stanzas[DEFAULT_CONFIGURATION] = defaults
    configurations: dict[str, Configuration] = {}
    refused: dict[str, str] = {}
    for name, values in stanzas.items():
        try:
            configurations[name] = _configuration(values)
        except ConfigError as exc:
            refused[name] = str(exc)
    app = AppConfig(
        thread_limit=_thread_limit(defaults, notices),
        max_response_body_length=_body_length(defaults, notices),
        configurations=configurations,
        refused=refused,
    )
    return app, notices


def load_app_config(client: SplunkdClient) -> tuple[AppConfig, list[Notice]]:
    return build_app_config(client.get_json(CONF_PATH, {}))


# ---- storage/passwords ------------------------------------------------------


@dataclass(frozen=True)
class StoredPassword:
    realm: str
    username: str
    clear_password: str = field(repr=False)


class PasswordStore:
    """The stored passwords in the order splunkd listed them. repr() shows counts
    only."""

    def __init__(self, stored: Sequence[StoredPassword] = ()) -> None:
        self._stored: tuple[StoredPassword, ...] = tuple(stored)

    def __repr__(self) -> str:
        return f"PasswordStore(entries={len(self._stored)})"

    def __len__(self) -> int:
        return len(self._stored)

    def input_password(self, stanza: str) -> str | None:
        """The first entry whose realm is the full stanza name (web_ping://<name>),
        whatever its user name, as Website Monitoring chose it."""
        for entry in self._stored:
            if entry.realm == stanza:
                return entry.clear_password
        return None

    def proxy_password(self) -> str | None:
        for entry in self._stored:
            if entry.realm == PROXY_REALM and entry.username == PROXY_USERNAME:
                return entry.clear_password
        return None


def build_password_store(document: Mapping[str, object]) -> PasswordStore:
    stored: list[StoredPassword] = []
    for _name, values in entries(document):
        realm = values.get("realm")
        username = values.get("username")
        clear = values.get("clear_password")
        if realm is None or username is None or clear is None:
            continue
        stored.append(StoredPassword(realm, username, clear))
    return PasswordStore(stored)


def load_passwords(client: SplunkdClient) -> PasswordStore:
    return build_password_store(client.get_json(PASSWORDS_PATH, {}))


# ---- cache ------------------------------------------------------------------


@dataclass(frozen=True)
class Snapshot:
    app: AppConfig
    passwords: PasswordStore
    generation: int
    """1 for the first load, one more for every successful refresh."""


class ConfigCache:
    """Holds the last good configuration and passwords and refreshes them every
    REFRESH_SECONDS. Call refresh_if_due() from one thread (the scheduler); any
    thread may read snapshot.

    A failed refresh keeps the old values with one WARN per run of failures. Until
    the first load succeeds snapshot is None, which means no check may run: a check
    sent directly while a proxy is configured would report a false outage.
    """

    def __init__(
        self,
        client: SplunkdClient,
        *,
        clock: Callable[[], float] = time.monotonic,
        logger: StanzaLogger = process_log,
        refresh_seconds: float = REFRESH_SECONDS,
        retry_seconds: float = RETRY_SECONDS,
    ) -> None:
        self._client: SplunkdClient = client
        self._clock: Callable[[], float] = clock
        self._log: StanzaLogger = logger
        self._refresh_seconds: float = refresh_seconds
        self._retry_seconds: float = retry_seconds
        self._lock: threading.Lock = threading.Lock()
        self._snapshot: Snapshot | None = None
        self._next_attempt: float = clock()
        self._failures: int = 0

    @property
    def snapshot(self) -> Snapshot | None:
        with self._lock:
            return self._snapshot

    def refresh_if_due(self) -> Snapshot | None:
        """Load when due (first load, retry or refresh); returns the snapshot to use."""
        now = self._clock()
        if now < self._next_attempt:
            return self.snapshot
        try:
            app, notices = load_app_config(self._client)
            passwords = load_passwords(self._client)
        except SplunkdError as exc:
            return self._failed(now, str(exc))
        with self._lock:
            generation = 1 if self._snapshot is None else self._snapshot.generation + 1
            self._snapshot = Snapshot(app, passwords, generation)
            snapshot = self._snapshot
        self._next_attempt = now + self._refresh_seconds
        if self._failures:
            self._log.info(
                "configuration read from splunkd after %d failed attempts",
                self._failures,
            )
        self._failures = 0
        for notice in notices:
            self._log.log(notice.level, "website_monitoring.conf: %s", notice.message)
        self._log.debug(
            "configuration loaded generation=%d configurations=%d refused=%d stored_passwords=%d",
            generation,
            len(app.configurations),
            len(app.refused),
            len(passwords),
        )
        return snapshot

    def _failed(self, now: float, error: str) -> Snapshot | None:
        self._failures += 1
        self._next_attempt = now + self._retry_seconds
        snapshot = self.snapshot
        if snapshot is None:
            if self._failures == 1:
                self._log.error(
                    "cannot read configuration from splunkd, no checks run until it"
                    " succeeds; retrying every %.0f s: %s",
                    self._retry_seconds,
                    error,
                )
            else:
                self._log.debug("configuration still not readable: %s", error)
            return None
        if self._failures == 1:
            self._log.warning(
                "cannot refresh configuration from splunkd, keeping the values"
                " loaded before; retrying every %.0f s: %s",
                self._retry_seconds,
                error,
            )
        else:
            self._log.debug("configuration refresh still failing: %s", error)
        return snapshot
