"""Read-only checks that the main Splunk on this host was not disturbed."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

PORTS = (8000, 8088, 8089, 9997)
TCP_TABLES = (Path("/proc/net/tcp"), Path("/proc/net/tcp6"))
LISTEN = "0A"


@dataclass(frozen=True)
class Snapshot:
    pid: int
    start_ticks: int
    listeners: dict[int, frozenset[tuple[int, int]]]
    """Per port, the (owner uid, socket inode) of each listener. Empty means absent."""


def main_pid() -> int:
    output = subprocess.run(
        ["systemctl", "show", "Splunkd", "-p", "MainPID", "--value"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    pid = int(output)
    if pid <= 0:
        raise RuntimeError(f"Splunkd has no main process (MainPID={output})")
    return pid


def start_ticks(pid: int) -> int:
    """Field 22 of /proc/<pid>/stat, after the command name in parentheses."""
    stat = Path(f"/proc/{pid}/stat").read_text()
    return int(stat.rsplit(")", 1)[1].split()[19])


def listeners() -> dict[int, frozenset[tuple[int, int]]]:
    found: dict[int, set[tuple[int, int]]] = {port: set() for port in PORTS}
    for table in TCP_TABLES:
        for line in table.read_text().splitlines()[1:]:
            fields = line.split()
            port = int(fields[1].rsplit(":", 1)[1], 16)
            if fields[3] == LISTEN and port in found:
                found[port].add((int(fields[7]), int(fields[9])))
    return {port: frozenset(sockets) for port, sockets in found.items()}


def take() -> Snapshot:
    pid = main_pid()
    return Snapshot(pid=pid, start_ticks=start_ticks(pid), listeners=listeners())


def compare(before: Snapshot, after: Snapshot) -> list[str]:
    differences: list[str] = []
    if before.pid != after.pid:
        differences.append(f"main splunkd process ID {before.pid} -> {after.pid}")
    if before.start_ticks != after.start_ticks:
        differences.append(
            f"main splunkd start time {before.start_ticks} -> {after.start_ticks}"
        )
    for port in PORTS:
        if before.listeners[port] != after.listeners[port]:
            differences.append(
                f"listeners on port {port}: {sorted(before.listeners[port])}"
                f" -> {sorted(after.listeners[port])}"
            )
    return differences
