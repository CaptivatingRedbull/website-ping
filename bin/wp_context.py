"""What one check needs, fixed when it is scheduled.

A CheckContext holds the stanza's settings plus what website_monitoring.conf and
storage/passwords give that stanza. The scheduler builds it from the latest
configuration, so a refresh never changes a check that is already running.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from logger import StanzaLogger
from ping_config import DEFAULT_SSL_VERIFY, Settings
from wp_names import CONF_FILE
from wp_proxy import proxy_warnings
from wp_splunk import (
    BUILTIN,
    DEFAULT_MAX_RESPONSE_BODY_LENGTH,
    ConfigCache,
    Configuration,
    ProxyConf,
    Snapshot,
)


@dataclass(frozen=True)
class CheckContext:
    settings: Settings
    proxy: ProxyConf = field(default_factory=ProxyConf)
    """The proxy of the input's configuration; an empty proxy_server means none.
    Kept even then, because proxy_ignore also applies to environment proxies."""
    password: str | None = field(default=None, repr=False)
    """Stored password of the stanza (realm web_ping://<name>)."""
    proxy_password: str | None = field(default=None, repr=False)
    ssl_verify: bool = DEFAULT_SSL_VERIFY
    """The input's ssl_verify, or its configuration's when the input leaves it blank."""
    ca_certs: str | None = None
    """The input's ca_certs, or its configuration's when the input leaves it blank."""
    max_response_body_length: int = DEFAULT_MAX_RESPONSE_BODY_LENGTH


def make_context(
    settings: Settings,
    configuration: Configuration = BUILTIN,
    *,
    password: str | None = None,
    proxy_password: str | None = None,
    max_response_body_length: int = DEFAULT_MAX_RESPONSE_BODY_LENGTH,
) -> CheckContext:
    """The context of one check. A value set in the input wins over the one of its
    configuration."""
    verify = settings["ssl_verify"]
    ca_certs = settings["ca_certs"]
    return CheckContext(
        settings=settings,
        proxy=configuration.proxy,
        password=password,
        proxy_password=proxy_password,
        ssl_verify=configuration.ssl_verify if verify is None else verify,
        ca_certs=configuration.ca_certs if ca_certs is None else ca_certs,
        max_response_body_length=max_response_body_length,
    )


class BuiltinContexts:
    """Website Monitoring's built-in values for every stanza, without splunkd."""

    def ready(self) -> bool:
        return True

    def context(self, settings: Settings, log: StanzaLogger) -> CheckContext | None:
        return make_context(settings)


class ConfigContexts:
    """Contexts from website_monitoring.conf and storage/passwords, through a
    ConfigCache. Used by the scheduler thread only."""

    def __init__(self, cache: ConfigCache) -> None:
        self._cache: ConfigCache = cache
        self._snapshot: Snapshot | None = None
        self._warned_unknown: set[str] = set()
        self._warned_no_password: set[str] = set()
        self._warned_proxy: set[tuple[str, str]] = set()
        """(stanza, warning) pairs already logged."""
        self._logged: dict[tuple[str, str], int] = {}
        """(stanza, what) -> generation it was last logged for."""

    def ready(self) -> bool:
        """Load or refresh the configuration when due. False until it was read
        once: then no check may start."""
        self._snapshot = self._cache.refresh_if_due()
        return self._snapshot is not None

    def context(self, settings: Settings, log: StanzaLogger) -> CheckContext | None:
        """None if the stanza must not run: no configuration loaded yet, or its
        configuration is refused."""
        snapshot = self._snapshot
        if snapshot is None:
            return None
        stanza = settings["stanza"]
        name = settings["configuration"]
        app = snapshot.app
        refusal = app.refusal(name)
        if refusal is not None:
            if self._first("refused", stanza, snapshot.generation):
                log.error(
                    "%s stanza %s cannot be used, not run: %s",
                    CONF_FILE,
                    name,
                    refusal,
                )
            return None
        configuration = app.configuration(name)
        if configuration is None:
            if stanza not in self._warned_unknown:
                self._warned_unknown.add(stanza)
                log.warning(
                    "%s has no stanza %s; using the built-in values (no proxy)",
                    CONF_FILE,
                    name,
                )
            configuration = BUILTIN
        password = snapshot.passwords.input_password(stanza)
        found = password is not None
        if found and self._first("password", stanza, snapshot.generation):
            log.debug("password found for stanza")
        if (
            not found
            and settings["username"] is not None
            and stanza not in self._warned_no_password
        ):
            self._warned_no_password.add(stanza)
            log.warning(
                "username is set, but storage/passwords has no password with realm %s;"
                " requests are sent without credentials",
                stanza,
            )
        proxy_password = snapshot.passwords.proxy_password()
        for warning in proxy_warnings(configuration.proxy, proxy_password):
            if (stanza, warning) not in self._warned_proxy:
                self._warned_proxy.add((stanza, warning))
                log.warning("%s stanza %s: %s", CONF_FILE, name, warning)
        return make_context(
            settings,
            configuration,
            password=password,
            proxy_password=proxy_password,
            max_response_body_length=app.max_response_body_length,
        )

    def _first(self, what: str, stanza: str, generation: int) -> bool:
        """True once per stanza and configuration load."""
        key = (what, stanza)
        if self._logged.get(key) == generation:
            return False
        self._logged[key] = generation
        return True
