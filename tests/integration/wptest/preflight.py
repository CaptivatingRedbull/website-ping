"""Isolation checks that stop a session before any build or container start."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import cast

LABEL = "website-ping.test"
MIN_FREE_DISK = 200 * 1024**3
DATA_ROOT = "/data/docker"
ALLOWED_STANZA_HOSTS = frozenset(
    {"target", "env-proxied", "wptest.invalid", "192.0.2.10", "münchen.test",
     "straße.test"}
)  # fmt: skip
"""The international names resolve only through the target's network aliases
(their punycode forms in the compose files); .test is a reserved top-level domain."""
FORBIDDEN_TEXT = "host.docker.internal"

TOP_KEYS = frozenset({"name", "services", "networks", "volumes"})
SERVICE_KEYS = frozenset(
    {
        "image",
        "build",
        "command",
        "entrypoint",
        "hostname",
        "environment",
        "labels",
        "mem_limit",
        "memswap_limit",
        "cpus",
        "ports",
        "volumes",
        "networks",
        "depends_on",
        "healthcheck",
    }
)
BUILD_KEYS = frozenset({"context", "dockerfile", "labels"})
PORT_KEYS = frozenset({"mode", "host_ip", "target", "protocol"})
SERVICE_VOLUME_KEYS = frozenset({"type", "source", "target", "volume"})
TOP_VOLUME_KEYS = frozenset({"name", "labels"})
TOP_NETWORK_KEYS = frozenset({"name", "ipam", "labels", "internal"})


@dataclass(frozen=True)
class Violation:
    rule: str
    path: str
    detail: str


def _mapping(value: object) -> dict[str, object]:
    return cast("dict[str, object]", value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return cast("list[object]", value) if isinstance(value, list) else []


def _unknown_keys(
    entry: dict[str, object], allowed: frozenset[str], path: str
) -> Iterator[Violation]:
    for key in entry:
        if key not in allowed:
            yield Violation(
                "unknown-setting", f"{path}.{key}", "not on the allowed list"
            )


def _strings(value: object, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    for key, item in _mapping(value).items():
        yield path, key
        yield from _strings(item, f"{path}.{key}")
    for index, item in enumerate(_sequence(value)):
        yield from _strings(item, f"{path}[{index}]")


def _check_port(entry: dict[str, object], path: str) -> Iterator[Violation]:
    if "published" in entry:
        yield Violation("fixed-host-port", f"{path}.published", str(entry["published"]))
    yield from _unknown_keys(entry, PORT_KEYS | {"published"}, path)
    if entry.get("host_ip") != "127.0.0.1":
        yield Violation(
            "port-not-loopback", f"{path}.host_ip", str(entry.get("host_ip"))
        )


def _check_service_volume(entry: dict[str, object], path: str) -> Iterator[Violation]:
    yield from _unknown_keys(entry, SERVICE_VOLUME_KEYS, path)
    if entry.get("type") != "volume":
        yield Violation("volume-type", f"{path}.type", str(entry.get("type")))


def _check_limits(service: dict[str, object], path: str) -> Iterator[Violation]:
    for key in ("mem_limit", "memswap_limit", "cpus"):
        if service.get(key) in (None, "", 0):
            yield Violation("missing-limit", f"{path}.{key}", "required")
    memory, swap = service.get("mem_limit"), service.get("memswap_limit")
    if memory is not None and swap is not None and str(memory) != str(swap):
        yield Violation(
            "swap-limit", f"{path}.memswap_limit", f"{swap} differs from {memory}"
        )


def _check_service(service: dict[str, object], path: str) -> Iterator[Violation]:
    yield from _unknown_keys(service, SERVICE_KEYS, path)
    if service.get("entrypoint") is not None:
        yield Violation("entrypoint", f"{path}.entrypoint", "must be null")
    yield from _check_limits(service, path)
    if _mapping(service.get("labels")).get(LABEL) != "true":
        yield Violation("missing-label", f"{path}.labels", f"{LABEL}=true is required")
    yield from _unknown_keys(
        _mapping(service.get("build")), BUILD_KEYS, f"{path}.build"
    )
    for index, entry in enumerate(_sequence(service.get("ports"))):
        yield from _check_port(_mapping(entry), f"{path}.ports[{index}]")
    for index, entry in enumerate(_sequence(service.get("volumes"))):
        yield from _check_service_volume(_mapping(entry), f"{path}.volumes[{index}]")


def check_compose(config: dict[str, object], label: str) -> list[Violation]:
    """Compare one rendered compose file, named by label, with the allowed list."""
    violations: list[Violation] = []
    for key in config:
        if key not in TOP_KEYS and not key.startswith("x-"):
            violations.append(
                Violation("unknown-setting", f"{label}.{key}", "not allowed")
            )
    for name, service in _mapping(config.get("services")).items():
        violations += _check_service(_mapping(service), f"{label}.services.{name}")
    for name, entry in _mapping(config.get("volumes")).items():
        violations += _unknown_keys(
            _mapping(entry), TOP_VOLUME_KEYS, f"{label}.volumes.{name}"
        )
    for name, entry in _mapping(config.get("networks")).items():
        violations += _unknown_keys(
            _mapping(entry), TOP_NETWORK_KEYS, f"{label}.networks.{name}"
        )
    for path, text in _strings(config, label):
        if FORBIDDEN_TEXT in text:
            violations.append(Violation("host-address", path, text))
    return violations


def check_stanza_urls(hosts: list[str]) -> list[Violation]:
    """Accept only the hosts on the test network and the reserved test names."""
    return [
        Violation("stanza-host", "inputs.conf", host)
        for host in hosts
        if host not in ALLOWED_STANZA_HOSTS
    ]


def check_data_root(data_root: str) -> list[Violation]:
    if data_root == DATA_ROOT:
        return []
    return [Violation("data-root", "docker info", f"{data_root}, expected {DATA_ROOT}")]


def check_disk(free_bytes: int) -> list[Violation]:
    if free_bytes >= MIN_FREE_DISK:
        return []
    return [
        Violation(
            "disk-space",
            "/data",
            f"{free_bytes // 1024**3} GB free, at least {MIN_FREE_DISK // 1024**3} GB needed",
        )
    ]


def check_memory(available_bytes: int, stack_limit_bytes: int) -> list[Violation]:
    needed = stack_limit_bytes + 4 * 1024**3
    if available_bytes >= needed:
        return []
    return [
        Violation(
            "memory",
            "/proc/meminfo",
            f"{available_bytes // 1024**2} MiB available, {needed // 1024**2} MiB needed",
        )
    ]
