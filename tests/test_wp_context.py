"""wp_context: the context of one check, from settings, website_monitoring.conf and
stored passwords."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest
from logger import StanzaLogger, log_to_stderr, setup_logging
from ping_config import Settings, build_settings
from wp_context import BuiltinContexts, CheckContext, ConfigContexts, make_context
from wp_splunk import (
    BUILTIN,
    CONF_PATH,
    PROXY_PASSWORD_REFUSED,
    ConfigCache,
    Configuration,
    ProxyConf,
    SplunkdError,
)

PASSWORD = "stored-password-must-not-be-logged"
PROXY_PASSWORD = "proxy-password-must-not-be-logged"


def settings(name: str = "a", **extra: str) -> Settings:
    built, _ = build_settings(
        f"web_ping://{name}",
        {"url": "http://example.invalid/", "interval": "60", **extra},
    )
    return built


def entry(name: str, **content: str) -> dict[str, object]:
    return {"name": name, "content": content}


class Splunkd:
    """website_monitoring.conf and storage/passwords as splunkd lists them."""

    def __init__(self) -> None:
        self.conf: list[dict[str, object]] = [
            entry("wp_defaults", max_response_body_length="500"),
            entry("proxied", proxy_server="squid", proxy_port="3128"),
            entry("plain", proxy_server="squid", proxy_password="in-conf"),
            entry("verified", ssl_verify="true", ca_certs="/etc/ca.pem"),
            entry("socks", proxy_server="squid", proxy_type="socks5"),
            entry(
                "noisy",
                proxy_server="squid",
                proxy_port="3128",
                proxy_user="wpproxy",
                proxy_ignore="target",
            ),
        ]
        self.passwords: list[dict[str, object]] = [
            entry("x", realm="web_ping://a", username="u", clear_password=PASSWORD),
            entry(
                "y",
                realm="website_monitoring_app_proxy",
                username="IN_CONF_FILE",
                clear_password=PROXY_PASSWORD,
            ),
        ]
        self.down: bool = False

    def get_json(self, path: str, params: Mapping[str, str]) -> Mapping[str, object]:
        if self.down:
            raise SplunkdError("down")
        return {"entry": self.conf if path == CONF_PATH else self.passwords}


class Clock:
    def __init__(self) -> None:
        self.now: float = 0.0

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


def make_contexts(splunkd: Splunkd, clock: Clock) -> ConfigContexts:
    return ConfigContexts(ConfigCache(splunkd, clock=clock))


def debug_log(stanza: str) -> StanzaLogger:
    return StanzaLogger(stanza, logging.DEBUG)


# ---- make_context -----------------------------------------------------------


def test_builtin_context() -> None:
    context = make_context(settings())
    assert context == CheckContext(settings())
    assert context.proxy == ProxyConf()
    assert context.ssl_verify is False and context.ca_certs is None
    assert context.max_response_body_length == 1000


def test_input_blank_takes_the_configuration_values() -> None:
    configuration = Configuration(ssl_verify=True, ca_certs="/etc/ca.pem")
    context = make_context(settings(), configuration)
    assert (context.ssl_verify, context.ca_certs) == (True, "/etc/ca.pem")


def test_input_values_win() -> None:
    configuration = Configuration(ssl_verify=True, ca_certs="/etc/ca.pem")
    context = make_context(
        settings(ssl_verify="false", ca_certs="/own.pem"), configuration
    )
    assert (context.ssl_verify, context.ca_certs) == (False, "/own.pem")


def test_context_repr_hides_passwords() -> None:
    context = make_context(settings(), password=PASSWORD, proxy_password=PROXY_PASSWORD)
    assert PASSWORD not in repr(context) and PROXY_PASSWORD not in repr(context)


def test_builtin_contexts_need_no_splunkd() -> None:
    contexts = BuiltinContexts()
    assert contexts.ready()
    assert contexts.context(settings(), debug_log("a")) == make_context(settings())


# ---- ConfigContexts ---------------------------------------------------------


def test_no_context_before_the_first_load() -> None:
    splunkd = Splunkd()
    splunkd.down = True
    contexts = make_contexts(splunkd, Clock())
    assert contexts.context(settings(), debug_log("a")) is None
    assert not contexts.ready()
    assert contexts.context(settings(), debug_log("a")) is None


def test_default_configuration() -> None:
    contexts = make_contexts(Splunkd(), Clock())
    assert contexts.ready()
    context = contexts.context(settings(), debug_log("web_ping://a"))
    assert context is not None
    assert context.proxy == ProxyConf()
    assert context.password == PASSWORD
    assert context.proxy_password == PROXY_PASSWORD
    assert context.max_response_body_length == 500


def test_named_configuration() -> None:
    contexts = make_contexts(Splunkd(), Clock())
    assert contexts.ready()
    log = debug_log("web_ping://b")
    proxied = contexts.context(settings("b", configuration="proxied"), log)
    assert proxied is not None
    assert proxied.proxy == ProxyConf(proxy_server="squid", proxy_port="3128")
    assert proxied.password is None
    verified = contexts.context(settings("b", configuration="verified"), log)
    assert verified is not None
    assert (verified.ssl_verify, verified.ca_certs) == (True, "/etc/ca.pem")


def test_unknown_configuration_warns_once_and_uses_builtin(log_file: Path) -> None:
    contexts = make_contexts(Splunkd(), Clock())
    assert contexts.ready()
    log = debug_log("web_ping://b")
    for _ in range(3):
        context = contexts.context(settings("b", configuration="nope"), log)
        assert context is not None
        assert context.proxy == BUILTIN.proxy
        assert context.ssl_verify is BUILTIN.ssl_verify
    warnings = [line for line in lines(log_file) if " WARN " in line]
    assert len(warnings) == 1
    assert "stanza=web_ping://b" in warnings[0]
    assert warnings[0].endswith(
        "website_monitoring.conf has no stanza nope; using the built-in values (no proxy)"
    )


def test_refused_configuration_does_not_run_and_logs_once_per_load(
    log_file: Path,
) -> None:
    clock = Clock()
    contexts = make_contexts(Splunkd(), clock)
    log = debug_log("web_ping://b")
    for _ in range(2):
        assert contexts.ready()
        for _ in range(3):
            assert contexts.context(settings("b", configuration="plain"), log) is None
        clock.now += 600
    errors = [line for line in lines(log_file) if " ERROR " in line]
    assert len(errors) == 2
    assert errors[0].endswith(
        f"website_monitoring.conf stanza plain cannot be used, not run: {PROXY_PASSWORD_REFUSED}"
    )
    assert all("in-conf" not in line for line in lines(log_file))


def test_password_found_is_logged_once_per_load(log_file: Path) -> None:
    clock = Clock()
    contexts = make_contexts(Splunkd(), clock)
    log = debug_log("web_ping://a")
    for _ in range(2):
        assert contexts.ready()
        for _ in range(3):
            _ = contexts.context(settings(), log)
        clock.now += 600
    found = [line for line in lines(log_file) if "password found for stanza" in line]
    assert len(found) == 2
    assert all(" DEBUG stanza=web_ping://a " in line for line in found)
    text = "\n".join(lines(log_file))
    assert PASSWORD not in text and PROXY_PASSWORD not in text


def test_a_refresh_failure_keeps_the_contexts() -> None:
    clock = Clock()
    splunkd = Splunkd()
    contexts = make_contexts(splunkd, clock)
    assert contexts.ready()
    splunkd.down = True
    clock.now += 600
    assert contexts.ready()
    context = contexts.context(settings(), debug_log("web_ping://a"))
    assert context is not None and context.password == PASSWORD


def test_socks_configuration_does_not_run(log_file: Path) -> None:
    contexts = make_contexts(Splunkd(), Clock())
    assert contexts.ready()
    log = debug_log("web_ping://b")
    assert contexts.context(settings("b", configuration="socks"), log) is None
    [error] = [line for line in lines(log_file) if " ERROR " in line]
    assert "stanza=web_ping://b" in error
    assert error.endswith(
        "website_monitoring.conf stanza socks cannot be used, not run:"
        " proxy_type = socks5 is not supported, only HTTP proxies are"
    )


def test_proxy_warnings_once_per_stanza(log_file: Path) -> None:
    clock = Clock()
    splunkd = Splunkd()
    splunkd.passwords = splunkd.passwords[:1]  # no stored proxy password
    contexts = make_contexts(splunkd, clock)
    for _ in range(2):
        assert contexts.ready()
        for stanza in ("b", "c", "b"):
            context = contexts.context(
                settings(stanza, configuration="noisy"),
                debug_log(f"web_ping://{stanza}"),
            )
            assert context is not None and context.proxy_password is None
        clock.now += 600
    ignore = (
        "website_monitoring.conf stanza noisy: proxy_ignore has no effect on a"
        " configured proxy, as in Website Monitoring"
    )
    no_password = (
        "website_monitoring.conf stanza noisy: proxy_user is set but no proxy"
        " password is stored (realm website_monitoring_app_proxy, user"
        " IN_CONF_FILE); requests go to the proxy without credentials"
    )
    warnings = [line for line in lines(log_file) if " WARN " in line]
    assert len(warnings) == 4
    for stanza in ("b", "c"):
        mine = [line for line in warnings if f"stanza=web_ping://{stanza} " in line]
        assert [line.split(" v=", 1)[1].split(" ", 1)[1] for line in mine] == [
            ignore,
            no_password,
        ]
