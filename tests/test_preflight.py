from __future__ import annotations

import copy
from typing import cast

import pytest
from wptest import preflight
from wptest.preflight import Violation, check_compose, check_stanza_urls

LABELS = {"website-ping.kept": "false", "website-ping.test": "true"}


def good_config() -> dict[str, object]:
    """A config in the shape `docker compose config --format json` renders."""
    return copy.deepcopy(
        {
            "name": "wptest-106-standalone-abc123",
            "networks": {
                "default": {
                    "name": "wptest-106-standalone-abc123_default",
                    "ipam": {},
                    "labels": LABELS,
                }
            },
            "services": {
                "so1": {
                    "cpus": 2,
                    "command": None,
                    "entrypoint": None,
                    "environment": {"SPLUNK_PASSWORD": "placeholder"},
                    "hostname": "so1",
                    "image": "splunk/splunk:10.6.1.1@sha256:2a7c",
                    "labels": LABELS,
                    "mem_limit": "2147483648",
                    "memswap_limit": "2147483648",
                    "networks": {"default": None},
                    "volumes": [
                        {
                            "type": "volume",
                            "source": "so1-etc",
                            "target": "/opt/splunk/etc",
                            "volume": {},
                        }
                    ],
                    "ports": [
                        {
                            "mode": "ingress",
                            "host_ip": "127.0.0.1",
                            "target": 8089,
                            "protocol": "tcp",
                        }
                    ],
                },
                "squid": {
                    "cpus": 0.5,
                    "command": None,
                    "entrypoint": None,
                    "labels": LABELS,
                    "mem_limit": "268435456",
                    "memswap_limit": "268435456",
                    "networks": {"default": None},
                    "build": {
                        "context": "/repo/tests/integration/squid",
                        "dockerfile": "Dockerfile",
                        "labels": LABELS,
                    },
                },
            },
            "volumes": {
                "so1-etc": {
                    "name": "wptest-106-standalone-abc123_so1-etc",
                    "labels": LABELS,
                }
            },
            "x-labels": LABELS,
        }
    )


def service(config: dict[str, object], name: str = "so1") -> dict[str, object]:
    return cast("dict[str, dict[str, object]]", config["services"])[name]


def first(config: dict[str, object], key: str) -> dict[str, object]:
    return cast("list[dict[str, object]]", service(config)[key])[0]


def rules(violations: list[Violation]) -> set[str]:
    return {violation.rule for violation in violations}


def test_accepts_the_rendered_format() -> None:
    assert check_compose(good_config(), "standalone") == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("network_mode", "host"),
        ("privileged", True),
        ("pid", "host"),
        ("ipc", "host"),
        ("extra_hosts", {"x": "1.2.3.4"}),
        ("cap_add", ["NET_ADMIN"]),
        ("devices", ["/dev/sda"]),
        ("security_opt", ["seccomp=unconfined"]),
        ("restart", "always"),
    ],
)
def test_rejects_unlisted_service_settings(key: str, value: object) -> None:
    config = good_config()
    service(config)[key] = value
    violations = check_compose(config, "standalone")
    assert "unknown-setting" in rules(violations)
    assert any(violation.path.endswith(f".{key}") for violation in violations)


def test_rejects_unknown_top_level_key() -> None:
    config = good_config()
    config["secrets"] = {}
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


def test_allows_extension_top_level_key() -> None:
    config = good_config()
    config["x-anything"] = {"privileged": True}
    assert check_compose(config, "standalone") == []


def test_rejects_entrypoint_override() -> None:
    config = good_config()
    service(config)["entrypoint"] = ["/bin/sh"]
    assert "entrypoint" in rules(check_compose(config, "standalone"))


def test_rejects_unknown_build_key() -> None:
    config = good_config()
    cast("dict[str, object]", service(config, "squid")["build"])["network"] = "host"
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


def test_rejects_fixed_host_port() -> None:
    config = good_config()
    first(config, "ports")["published"] = "18089"
    assert "fixed-host-port" in rules(check_compose(config, "standalone"))


def test_rejects_port_not_on_loopback() -> None:
    config = good_config()
    first(config, "ports")["host_ip"] = "0.0.0.0"
    assert "port-not-loopback" in rules(check_compose(config, "standalone"))


def test_rejects_port_without_host_ip() -> None:
    config = good_config()
    del first(config, "ports")["host_ip"]
    assert "port-not-loopback" in rules(check_compose(config, "standalone"))


def test_rejects_unknown_port_key() -> None:
    config = good_config()
    first(config, "ports")["app_protocol"] = "http"
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


def test_rejects_bind_mount() -> None:
    config = good_config()
    first(config, "volumes")["type"] = "bind"
    assert "volume-type" in rules(check_compose(config, "standalone"))


def test_rejects_unknown_service_volume_key() -> None:
    config = good_config()
    first(config, "volumes")["bind"] = {"propagation": "rshared"}
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


@pytest.mark.parametrize("key", ["driver_opts", "external"])
def test_rejects_top_level_volume_settings(key: str) -> None:
    config = good_config()
    cast("dict[str, dict[str, object]]", config["volumes"])["so1-etc"][key] = True
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


def test_rejects_unknown_top_level_network_setting() -> None:
    config = good_config()
    cast("dict[str, dict[str, object]]", config["networks"])["default"]["driver"] = (
        "macvlan"
    )
    assert "unknown-setting" in rules(check_compose(config, "standalone"))


@pytest.mark.parametrize("key", ["mem_limit", "memswap_limit", "cpus"])
def test_rejects_missing_limit(key: str) -> None:
    config = good_config()
    del service(config)[key]
    assert "missing-limit" in rules(check_compose(config, "standalone"))


def test_rejects_swap_different_from_memory() -> None:
    config = good_config()
    service(config)["memswap_limit"] = "4294967296"
    assert "swap-limit" in rules(check_compose(config, "standalone"))


def test_rejects_missing_label() -> None:
    config = good_config()
    service(config)["labels"] = {"other": "true"}
    assert "missing-label" in rules(check_compose(config, "standalone"))


def test_rejects_host_docker_internal_in_any_value() -> None:
    config = good_config()
    cast("dict[str, object]", service(config)["environment"])["X"] = (
        "http://host.docker.internal:8089"
    )
    assert "host-address" in rules(check_compose(config, "standalone"))


def test_stanza_hosts_accepted() -> None:
    assert (
        check_stanza_urls(["target", "env-proxied", "wptest.invalid", "192.0.2.10"])
        == []
    )


@pytest.mark.parametrize(
    "host", ["localhost", "127.0.0.1", "10.212.0.1", "192.168.8.2", "example.com"]
)
def test_stanza_host_rejected(host: str) -> None:
    assert rules(check_stanza_urls([host])) == {"stanza-host"}


def test_data_root() -> None:
    assert preflight.check_data_root("/data/docker") == []
    assert rules(preflight.check_data_root("/var/lib/docker")) == {"data-root"}


def test_disk_threshold() -> None:
    assert preflight.check_disk(200 * 1024**3) == []
    assert rules(preflight.check_disk(200 * 1024**3 - 1)) == {"disk-space"}


def test_memory_threshold() -> None:
    limits = 3 * 1024**3
    assert preflight.check_memory(limits + 4 * 1024**3, limits) == []
    assert rules(preflight.check_memory(limits + 4 * 1024**3 - 1, limits)) == {"memory"}
