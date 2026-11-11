"""Session fixtures: preflight, lock, host snapshot, the package and one stack at a time."""

from __future__ import annotations

import configparser
import fcntl
import os
import shlex
import shutil
from collections.abc import Callable, Generator, Iterator
from datetime import datetime
from pathlib import Path
from typing import IO
from urllib.parse import urlparse

import pytest
from wptest import evidence as evidence_module
from wptest import host_snapshot, install, preflight
from wptest.certs import Certificates, generate
from wptest.evidence import Evidence
from wptest.install import APPS_DIR, Package
from wptest.stack import (
    COMPOSE_FILES,
    INTEGRATION,
    Stack,
    docker,
    memory_limit,
    render,
    write_env_file,
)
from wptest.versions import LINES
from wptest.wait import HEALTHY, PROBE, STARTED, Stages, wait_for

TERMS_VAR = "WPTEST_ACCEPT_SPLUNK_TERMS"
EXTRA_COMPOSE_VAR = "WPTEST_EXTRA_COMPOSE"
LOCK_FILE = evidence_module.EVIDENCE_ROOT / "run.lock"
HEALTHY_TIMEOUT = 600
EVENT_TIMEOUT = 120
TOPOLOGY_OF_MARKER = {
    "single": "standalone",
    "network": "standalone",
    "no_route": "noroute",
    "distributed": "distributed",
}
TOPOLOGY_ORDER = ("standalone", "noroute", "distributed")
MANAGER_KEY = pytest.StashKey["StackManager"]()


def selected_lines(config: pytest.Config) -> list[str]:
    choice = str(config.getoption("--splunk-line"))
    return list(LINES) if choice == "all" else [choice]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "splunk_line" in metafunc.fixturenames:
        metafunc.parametrize("splunk_line", selected_lines(metafunc.config))


def _topology(item: pytest.Item) -> str | None:
    for marker, topology in TOPOLOGY_OF_MARKER.items():
        if item.get_closest_marker(marker):
            return topology
    return None


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Group tests by line, then topology, so each stack starts once."""
    lines = list(LINES)

    def key(item: pytest.Item) -> tuple[int, int]:
        callspec = getattr(item, "callspec", None)
        line = callspec.params.get("splunk_line") if callspec is not None else None
        topology = _topology(item)
        return (
            lines.index(line) if line in lines else len(lines),
            TOPOLOGY_ORDER.index(topology) if topology else len(TOPOLOGY_ORDER),
        )

    items.sort(key=key)


# ---- Preflight -------------------------------------------------------------


def stanza_hosts() -> list[str]:
    """Hosts of every test stanza URL. A value with no host (bad-config) is left out."""
    hosts: list[str] = []
    for path in sorted(APPS_DIR.glob("*/default/inputs.conf")):
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, delimiters=("=",)
        )
        parser.read(path, encoding="utf-8")
        for section in parser.sections():
            host = urlparse(parser.get(section, "url", fallback="")).hostname
            if host:
                hosts.append(host)
    return hosts


def compose_files() -> list[Path]:
    extra = [
        Path(p) for p in os.environ.get(EXTRA_COMPOSE_VAR, "").split(os.pathsep) if p
    ]
    return [*COMPOSE_FILES.values(), *extra]


def run_preflight(lines: list[str], workdir: Path) -> list[preflight.Violation]:
    violations: list[preflight.Violation] = []
    for line in lines:
        env_file = write_env_file(
            workdir / f"preflight-{line}.env", line, "placeholder", False
        )
        for path in compose_files():
            config = render(path, env_file, f"wptest-preflight-{line.replace('.', '')}")
            violations += preflight.check_compose(config, f"{path.name}[{line}]")
    violations += preflight.check_stanza_urls(stanza_hosts())
    violations += preflight.check_data_root(
        docker("info", "--format", "{{.DockerRootDir}}").strip()
    )
    violations += preflight.check_disk(shutil.disk_usage("/data").free)
    return violations


def available_memory() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("MemAvailable missing from /proc/meminfo")


def leftover_stacks() -> list[str]:
    output = docker(
        "ps", "-a", "--filter", f"label={preflight.LABEL}=true",
        "--format", '{{.Label "com.docker.compose.project"}} {{.Label "website-ping.kept"}}',
    )  # fmt: skip
    projects = {
        line.split()[0] for line in output.splitlines() if line.split()[1:] != ["true"]
    }
    return sorted(projects)


# ---- Stacks ----------------------------------------------------------------


class StackManager:
    """Starts and stops one stack at a time, keyed by line and topology."""

    def __init__(
        self,
        evidence: Evidence,
        package: Package,
        certificates: Certificates,
        workdir: Path,
        keep: bool,
    ) -> None:
        self.evidence = evidence
        self.package = package
        self.certificates = certificates
        self.workdir = workdir
        self.keep = keep
        self.current: Stack | None = None
        self.kept: Stack | None = None

    def get(self, line: str, topology: str) -> Stack:
        current = self.current
        if current is not None and (current.line, current.topology) == (line, topology):
            if current.setup_error is not None:
                raise current.setup_error
            return current
        self.stop_current()
        self._resource_gate(topology, line)
        stack = Stack(line, topology, self.workdir, kept=self.keep)
        self.current = stack
        self.evidence.note(f"{stack.project}.image", LINES[line].pinned_image)
        try:
            SETUPS[topology](stack, self)
        except BaseException as exc:
            stack.setup_error = exc
            stack.failed = True
            raise
        return stack

    def _resource_gate(self, topology: str, line: str) -> None:
        env_file = write_env_file(self.workdir / "gate.env", line, "placeholder", False)
        needed = memory_limit(render(COMPOSE_FILES[topology], env_file, "wptest-gate"))
        violations = preflight.check_memory(available_memory(), needed)
        violations += preflight.check_disk(shutil.disk_usage("/data").free)
        if violations:
            pytest.exit(
                "resource gate: "
                + "; ".join(f"{v.rule}: {v.detail}" for v in violations),
                returncode=3,
            )

    def mark_failed(self) -> None:
        if self.current is not None:
            self.current.failed = True

    def save_failure(self, stack: Stack) -> None:
        folder = stack.project
        save = self.evidence.save
        for service in stack.splunk_services:
            for name, script in (
                ("splunkd.log", "cat /opt/splunk/var/log/splunk/splunkd.log\n"),
                (
                    "modinput.log",
                    "grep -h web_ping /opt/splunk/var/log/splunk/splunkd.log || true\n",
                ),
            ):
                try:
                    save(
                        folder,
                        f"{service}-{name}",
                        stack.exec(service, script),
                        stack.password,
                    )
                except Exception as exc:  # noqa: BLE001 - keep collecting
                    save(folder, f"{service}-{name}.error", str(exc), stack.password)
        services = stack.compose("config", "--services").split()
        for service in services:
            try:
                save(
                    folder,
                    f"{service}-container.log",
                    stack.logs(service),
                    stack.password,
                )
            except Exception as exc:  # noqa: BLE001
                save(folder, f"{service}-container.log.error", str(exc), stack.password)
        for service, searcher in stack.searchers.items():
            save(
                folder,
                f"{service}-last-search.json",
                searcher.last_result,
                stack.password,
            )
        save(
            folder, "stages.txt", "\n".join(stack.stages.passed) + "\n", stack.password
        )

    def stop_current(self) -> None:
        stack, self.current = self.current, None
        if stack is None:
            return
        if stack.failed:
            self.save_failure(stack)
        if stack.failed and self.keep and self.kept is None:
            self.kept = stack
            path = self.evidence.save_password(stack.password)
            print(f"\nkept stack {stack.project}; admin password in {path}")
            return
        stack.down()


def _deliver_helpers(
    stack: Stack, manager: StackManager, splunk: tuple[str, ...]
) -> None:
    """Certificates and target code copied in, then the target is started."""
    for service in splunk:
        stack.cp(manager.certificates.ca, service, "/tmp/wptest-ca.pem")
    if "target" not in stack.compose("config", "--services").split():
        return
    stack.exec("target", "mkdir -p /srv/certs\n", user="root")
    stack.cp(INTEGRATION / "target" / "server.py", "target", "/srv/server.py")
    for path in manager.certificates.server_files:
        stack.cp(path, "target", f"/srv/certs/{path.name}")
    stack.exec("target", "touch /srv/go\n", user="root")
    wait_for(
        "target listening",
        lambda: True if '"listening"' in stack.logs("target") else None,
        60,
        stack.stages,
        interval=1,
    )


def _probe(stack: Stack, manager: StackManager, services: tuple[str, ...]) -> None:
    problems: list[str] = []
    results: dict[str, object] = {}
    for service in services:
        result = stack.probe(service)
        results[service] = {f"{h}:{p}": c for (h, p), c in result.classes.items()}
        problems += result.problems()
    manager.evidence.note(f"{stack.project}.probe", results)
    if problems:
        raise stack.stages.fail(PROBE, "; ".join(problems))
    stack.stages.reached(PROBE)


def _start(stack: Stack, manager: StackManager) -> None:
    try:
        stack.up(HEALTHY_TIMEOUT)
    except Exception as exc:
        raise stack.stages.fail(HEALTHY, str(exc)) from exc
    stack.stages.reached(HEALTHY)
    manager.evidence.note(
        f"{stack.project}.image_id", stack.container_image(stack.splunk_services[0])
    )


def _config_archive(manager: StackManager, app: str) -> Path:
    return install.build_config_app(
        APPS_DIR / app, manager.workdir / f"website_ping_inputs-{app}.tar.gz"
    )


def setup_standalone(stack: Stack, manager: StackManager) -> None:
    _start(stack, manager)
    _deliver_helpers(stack, manager, ("so1",))
    _probe(stack, manager, ("so1",))
    install.install_single(
        stack, "so1", manager.package, _config_archive(manager, "standalone"), True
    )
    install.wait_registered(stack, "so1", "status-200", stack.stages)
    wait_for(
        STARTED,
        lambda: True if stack.target_log() else None,
        EVENT_TIMEOUT,
        stack.stages,
    )


def _logged_since(stack: Stack, service: str, text: str, since: float) -> bool:
    """Whether splunkd.log has a line containing text, timestamped at or after since."""
    output = stack.exec(
        service,
        f"grep -F {shlex.quote(text)} /opt/splunk/var/log/splunk/splunkd.log || true\n",
    )
    for line in output.splitlines():
        stamp = " ".join(line.split()[:3])
        try:
            logged = datetime.strptime(stamp, "%m-%d-%Y %H:%M:%S.%f %z").timestamp()
        except ValueError:
            continue
        if logged >= since:
            return True
    return False


def setup_noroute(stack: Stack, manager: StackManager) -> None:
    _start(stack, manager)
    _deliver_helpers(stack, manager, ("so1",))
    _probe(stack, manager, ("so1",))
    install.install_single(
        stack, "so1", manager.package, _config_archive(manager, "no_route"), True
    )
    install.wait_registered(stack, "so1", "no-direct-route", stack.stages)
    wait_for(
        STARTED,
        lambda: (
            True
            if _logged_since(
                stack,
                "so1",
                "stanza=web_ping://no-direct-route starting check",
                stack.mark,
            )
            else None
        ),
        EVENT_TIMEOUT,
        stack.stages,
    )


SETUPS: dict[str, Callable[[Stack, StackManager], None]] = {
    "standalone": setup_standalone,
    "noroute": setup_noroute,
}


# ---- Fixtures --------------------------------------------------------------


class Harness:
    def __init__(self, evidence: Evidence, before: host_snapshot.Snapshot) -> None:
        self.evidence = evidence
        self.before = before


def _take_lock() -> IO[str]:
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    handle = LOCK_FILE.open("w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        pytest.exit(f"another session holds the lock {LOCK_FILE}", returncode=3)
    return handle


@pytest.fixture(scope="session", autouse=True)
def harness(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Harness]:
    if os.environ.get(TERMS_VAR) != "yes":
        pytest.exit(
            f"set {TERMS_VAR}=yes to accept Splunk's license and General Terms "
            "for the test containers",
            returncode=3,
        )
    lock = _take_lock()
    workdir = tmp_path_factory.mktemp("preflight")
    violations = run_preflight(selected_lines(request.config), workdir)
    if violations:
        pytest.exit(
            "preflight refused the session:\n"
            + "\n".join(f"  {v.rule}: {v.path}: {v.detail}" for v in violations),
            returncode=3,
        )
    leftovers = leftover_stacks()
    if leftovers:
        print(
            f"\nlabelled stacks not marked as kept: {', '.join(leftovers)}"
            " (remove them with scripts/test-clean.sh)"
        )
    before = host_snapshot.take()
    evidence = Evidence()
    evidence.note(
        "host_snapshot_before", {"pid": before.pid, "start_ticks": before.start_ticks}
    )
    yield Harness(evidence, before)
    differences = host_snapshot.compare(before, host_snapshot.take())
    evidence.note("host_snapshot_differences", differences)
    lock.close()
    if differences:
        pytest.fail("the main Splunk changed: " + "; ".join(differences), pytrace=False)


@pytest.fixture(scope="session")
def package(harness: Harness) -> Package:
    stages = Stages()
    try:
        built = install.build_package()
    except Exception as exc:
        raise stages.fail("build", str(exc)) from exc
    harness.evidence.note("tarball_sha256", built.sha256)
    harness.evidence.note("tarball", str(built.path))
    harness.evidence.note("working_tree_dirty", built.dirty)
    return built


@pytest.fixture(scope="session")
def certificates(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return generate(tmp_path_factory.mktemp("certs"))


@pytest.fixture(scope="session")
def stacks(
    request: pytest.FixtureRequest,
    harness: Harness,
    package: Package,
    certificates: Certificates,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[StackManager]:
    manager = StackManager(
        harness.evidence,
        package,
        certificates,
        tmp_path_factory.mktemp("stacks"),
        keep=bool(request.config.getoption("--keep")),
    )
    request.config.stash[MANAGER_KEY] = manager
    yield manager
    manager.stop_current()


@pytest.fixture
def standalone(stacks: StackManager, splunk_line: str) -> Stack:
    return stacks.get(splunk_line, "standalone")


@pytest.fixture
def no_route_stack(stacks: StackManager, splunk_line: str) -> Stack:
    return stacks.get(splunk_line, "noroute")


@pytest.fixture
def evidence(harness: Harness) -> Evidence:
    return harness.evidence


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    manager = item.config.stash.get(MANAGER_KEY, None)
    if report.failed and manager is not None:
        manager.mark_failed()
        if manager.keep:
            item.session.shouldstop = "--keep: stopping at the first failing stack"
    return report
