"""A docker compose wrapper that runs one labelled test stack at a time."""

from __future__ import annotations

import json
import secrets
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from wptest.splunk_rest import Searcher, SplunkCli, SplunkRest
from wptest.versions import LINES
from wptest.wait import Stages

INTEGRATION = Path(__file__).absolute().parent.parent
COMPOSE_DIR = INTEGRATION / "compose"
COMPOSE_FILES = {
    "standalone": COMPOSE_DIR / "standalone.yml",
    "noroute": COMPOSE_DIR / "no_route.yml",
    "distributed": COMPOSE_DIR / "distributed.yml",
    "spike": COMPOSE_DIR / "standalone.yml",
}
SPLUNK_SERVICES = {
    "standalone": ("so1",),
    "noroute": ("so1",),
    "distributed": ("ds", "idx", "sh", "hf"),
    "spike": ("so1",),
}
HOST_PORTS = (8000, 8088, 8089, 9997)
SPLUNK = "/opt/splunk/bin/splunk"
TARGET_PORT = 8080
CLOSED_TARGET_PORT = 8090


def docker(*args: str, stdin: str | None = None, timeout: float = 900) -> str:
    result = subprocess.run(
        ["docker", *args],
        check=False,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise DockerError(args, result.returncode, result.stdout, result.stderr)
    return result.stdout


class DockerError(RuntimeError):
    def __init__(
        self, args: tuple[str, ...], code: int, stdout: str, stderr: str
    ) -> None:
        super().__init__(
            f"docker {' '.join(args[:6])} exited {code}\n"
            f"stdout: {stdout[-3000:]}\nstderr: {stderr[-3000:]}"
        )
        self.stdout = stdout
        self.stderr = stderr


def project_name(line: str, topology: str) -> str:
    return f"wptest-{line.replace('.', '')}-{topology}-{secrets.token_hex(3)}"


def write_env_file(path: Path, line: str, password: str, kept: bool) -> Path:
    """The compose variables. Mode 600 because it holds the admin password."""
    values = {
        "WPTEST_SPLUNK_IMAGE": LINES[line].pinned_image,
        "WPTEST_PASSWORD": password,
        "WPTEST_KEPT": "true" if kept else "false",
        **LINES[line].licence_env,
    }
    path.touch(mode=0o600)
    path.chmod(0o600)
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return path


def render(compose_file: Path, env_file: Path, project: str) -> dict[str, object]:
    output = docker(
        "compose", "-p", project, "-f", str(compose_file),
        "--env-file", str(env_file), "config", "--format", "json",
    )  # fmt: skip
    return cast("dict[str, object]", json.loads(output))


def memory_limit(config: dict[str, object]) -> int:
    services = cast("dict[str, dict[str, object]]", config.get("services", {}))
    return sum(int(str(service.get("mem_limit", 0))) for service in services.values())


def lan_address() -> str:
    """The host's address on its default route. A UDP connect sends no packet."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        return cast(str, probe.getsockname()[0])


PROBE_SCRIPT = r"""
probe() {
  out=$(timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then class=connected
  elif [ $rc -eq 124 ]; then class=filtered
  elif printf '%s' "$out" | grep -qi refused; then class=refused
  elif printf '%s' "$out" | grep -qi 'network is unreachable'; then class=unreachable
  else class="other:$(printf '%s' "$out" | tr -s ' \n' '__' | tail -c 120)"; fi
  echo "$1 $2 $class"
}
"""


INPUT_PROCESS_SCRIPT = r"""
end=$((SECONDS+40))
while [ $SECONDS -lt $end ]; do
  for d in /proc/[0-9]*; do
    grep -qa 'web_ping[.]py' "$d/cmdline" 2>/dev/null || continue
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    case "$(basename "$exe")" in python*) ;; *) continue ;; esac
    echo "exe=$exe"
    tr '\0' '\n' < "$d/environ" 2>/dev/null \
      | grep -E '^(HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|NO_PROXY|no_proxy|SSL_CERT_FILE)='
    exit 0
  done
  sleep 0.2
done
echo "no web_ping.py process seen in 40 s" >&2
exit 1
"""


@dataclass
class ProbeResult:
    service: str
    expected: dict[tuple[str, int], str]
    classes: dict[tuple[str, int], str] = field(
        default_factory=dict[tuple[str, int], str]
    )

    def problems(self) -> list[str]:
        return [
            f"{self.service}: {host}:{port} was {self.classes.get((host, port), 'not tried')},"
            f" expected {expected}"
            for (host, port), expected in self.expected.items()
            if self.classes.get((host, port)) != expected
        ]


class Stack:
    """One compose project. Every command passes the env file; no password in arguments."""

    def __init__(self, line: str, topology: str, workdir: Path, kept: bool) -> None:
        self.line = line
        self.topology = topology
        self.project = project_name(line, topology)
        self.password = "Wp" + secrets.token_urlsafe(18)
        workdir.mkdir(parents=True, exist_ok=True)
        self.env_file = write_env_file(
            workdir / f"{self.project}.env", line, self.password, kept
        )
        self.compose_file = COMPOSE_FILES[topology]
        self.stages = Stages()
        self.failed = False
        self.setup_error: BaseException | None = None
        self.keep_requested = False
        self.mark = 0.0
        self.searchers: dict[str, Searcher] = {}
        self.facts: dict[str, object] = {}

    """What setup observed that the tests check, such as deployment delivery."""

    @property
    def splunk_services(self) -> tuple[str, ...]:
        return SPLUNK_SERVICES[self.topology]

    def compose(
        self, *args: str, stdin: str | None = None, timeout: float = 900
    ) -> str:
        return docker(
            "compose", "-p", self.project, "-f", str(self.compose_file),
            "--env-file", str(self.env_file), *args,
            stdin=stdin, timeout=timeout,
        )  # fmt: skip

    def up(self, timeout: int) -> None:
        self.compose(
            "up", "-d", "--build", "--quiet-pull", "--wait", "--wait-timeout", str(timeout),
            timeout=timeout + 300,
        )  # fmt: skip

    def down(self) -> None:
        self.compose(
            "down", "-v", "--remove-orphans", "--rmi", "local", "--timeout", "30"
        )

    def exec(
        self,
        service: str,
        script: str,
        user: str = "splunk",
        env: dict[str, str] | None = None,
        timeout: float = 600,
    ) -> str:
        """Run a bash script given on standard input, so it never shows in arguments."""
        options = ["-T", "-u", user]
        for key, value in (env or {}).items():
            options += ["-e", f"{key}={value}"]
        return self.compose(
            "exec", *options, service, "bash", "-s", stdin=script, timeout=timeout
        )

    def splunk(self, service: str, command: str, timeout: float = 600) -> str:
        """A Splunk CLI command, authenticated by SPLUNK_PASSWORD already in the container."""
        return self.exec(
            service,
            f"{SPLUNK} {command}\n",
            env={"SPLUNK_USERNAME": "admin"},
            timeout=timeout,
        )

    def cp(self, source: Path, service: str, destination: str) -> None:
        self.compose("cp", str(source), f"{service}:{destination}")

    def logs(self, service: str) -> str:
        return self.compose("logs", "--no-color", "--no-log-prefix", service)

    def port(self, service: str, container_port: int) -> int:
        output = self.compose("port", service, str(container_port)).strip()
        host, _, port = output.rpartition(":")
        if host != "127.0.0.1":
            raise RuntimeError(f"{service}:{container_port} published on {output}")
        return int(port)

    def container_image(self, service: str) -> str:
        container = self.compose("ps", "-q", service).strip()
        return docker(
            "container", "inspect", "--format", "{{.Image}}", container
        ).strip()

    def input_process(self, service: str) -> dict[str, str]:
        """exe and proxy and certificate variables of a running web_ping.py.

        Stanzas at 15 seconds include hang, which runs 5 seconds, so one is caught
        within 40 seconds.
        """
        output = self.exec(service, INPUT_PROCESS_SCRIPT, timeout=60)
        return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)

    def target_log(self) -> list[dict[str, object]]:
        """The target's JSON log lines after the most recent mark."""
        records: list[dict[str, object]] = []
        for line in self.logs("target").splitlines():
            try:
                record = cast("dict[str, object]", json.loads(line))
            except json.JSONDecodeError:
                continue
            if record.get("mark"):
                records = []
            elif "path" in record:
                records.append(record)
        return records

    def target_requests(self, title: str) -> int:
        """Requests logged after the mark whose path has the title as one segment."""
        return sum(
            1 for record in self.target_log() if title in str(record["path"]).split("/")
        )

    def rest(self, service: str) -> SplunkRest:
        return SplunkRest(self.port(service, 8089), self.password)

    def cli(self, service: str) -> SplunkCli:
        return SplunkCli(
            lambda command: self.exec(
                service, command + "\n", env={"SPLUNK_USERNAME": "admin"}
            )
        )

    def searcher(self, service: str) -> Searcher:
        if service not in self.searchers:
            self.searchers[service] = (
                self.cli(service) if self.topology == "noroute" else self.rest(service)
            )
        return self.searchers[service]

    def network_gateway(self) -> str:
        """The host's address on the stack's network, from Docker's IPAM settings."""
        network = f"{self.project}_default"
        config = json.loads(
            docker("network", "inspect", network, "--format", "{{json .IPAM.Config}}")
        )
        return str(cast("list[dict[str, object]]", config)[0]["Gateway"])

    def probe(self, service: str) -> ProbeResult:
        """Controls on the target, then the host's addresses on the four ports.

        The firewall rule drops packets to the gateway, so it must be filtered.
        The LAN address is filtered too, except on the internal-only network,
        which has no route to it.
        """
        lan = "unreachable" if self.topology == "noroute" else "filtered"
        expected = {
            ("target", TARGET_PORT): "connected",
            ("target", CLOSED_TARGET_PORT): "refused",
        }
        for port in HOST_PORTS:
            expected[(self.network_gateway(), port)] = "filtered"
            expected[(lan_address(), port)] = lan
        lines = [PROBE_SCRIPT]
        lines += [f"probe {host} {port} &" for host, port in expected]
        lines.append("wait")
        output = self.exec(service, "\n".join(lines) + "\n", timeout=60)
        result = ProbeResult(service, expected)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3:
                result.classes[(parts[0], int(parts[1]))] = parts[2]
        return result
