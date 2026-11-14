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
from wptest import host_snapshot, install, legacy, parity, preflight
from wptest.certs import SPLUNK_CERT_DIR, Certificates, generate
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
from wptest.versions import ALL_RUNTIMES, LINES, Runtime, select_runtimes
from wptest.wait import HEALTHY, INSTALL, PROBE, STARTED, Stages, wait_for

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
    "spike": "spike",
    "golden": "golden",
}
TOPOLOGY_ORDER = ("standalone", "noroute", "spike", "golden", "distributed")
OPT_IN_MARKERS = ("spike", "golden")
OWN_INTERPRETER_MARKERS = ("spike", "golden")
"""Tests of apps that are not website-ping and choose their interpreter themselves."""
MANAGER_KEY = pytest.StashKey["StackManager"]()


def selected_runtimes(config: pytest.Config) -> list[Runtime]:
    python = config.getoption("--python")
    try:
        return select_runtimes(
            str(config.getoption("--splunk-line")),
            None if python is None else str(python),
        )
    except ValueError as exc:
        raise pytest.UsageError(str(exc)) from exc


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "runtime" in metafunc.fixturenames:
        runtimes = selected_runtimes(metafunc.config)
        metafunc.parametrize("runtime", runtimes, ids=[r.id for r in runtimes])


def _topology(item: pytest.Item) -> str | None:
    for marker, topology in TOPOLOGY_OF_MARKER.items():
        if item.get_closest_marker(marker):
            return topology
    return None


def _deselect_opt_in(config: pytest.Config, items: list[pytest.Item]) -> None:
    expression = str(config.getoption("markexpr") or "")
    skipped = [m for m in OPT_IN_MARKERS if m not in expression]
    deselected = [i for i in items if any(i.get_closest_marker(m) for m in skipped)]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [i for i in items if i not in deselected]


def _deselect_interpreter_overrides(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """The python.required override only reaches website-ping's config app."""

    def overridden(item: pytest.Item) -> bool:
        callspec = getattr(item, "callspec", None)
        runtime = callspec.params.get("runtime") if callspec is not None else None
        return isinstance(runtime, Runtime) and runtime.overridden

    deselected = [
        i
        for i in items
        if overridden(i)
        and any(i.get_closest_marker(m) for m in OWN_INTERPRETER_MARKERS)
    ]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [i for i in items if i not in deselected]


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Drop opt-in tests and interpreter variants of other apps' tests, then group
    by runtime and topology so each stack starts once"""
    _deselect_opt_in(config, items)
    _deselect_interpreter_overrides(config, items)
    runtimes = list(ALL_RUNTIMES)

    def key(item: pytest.Item) -> tuple[int, int]:
        callspec = getattr(item, "callspec", None)
        runtime = callspec.params.get("runtime") if callspec is not None else None
        topology = _topology(item)
        return (
            runtimes.index(runtime) if runtime in runtimes else len(runtimes),
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
    for scenario in parity.PARITY_SCENARIOS:
        host = urlparse(scenario.url).hostname
        if host:
            hosts.append(host)
    return hosts


def compose_files() -> list[Path]:
    extra = [
        Path(p) for p in os.environ.get(EXTRA_COMPOSE_VAR, "").split(os.pathsep) if p
    ]
    return [*dict.fromkeys(COMPOSE_FILES.values()), *extra]


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
    """Starts and stops one stack at a time, keyed by runtime and topology."""

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

    def get(self, runtime: Runtime, topology: str) -> Stack:
        current = self.current
        if current is not None and (current.runtime, current.topology) == (
            runtime,
            topology,
        ):
            if current.setup_error is not None:
                raise current.setup_error
            return current
        self.stop_current()
        self._resource_gate(topology, runtime.line)
        stack = Stack(runtime, topology, self.workdir, kept=self.keep)
        self.current = stack
        self.evidence.note(f"{stack.project}.image", LINES[runtime.line].pinned_image)
        self.evidence.note(f"{stack.project}.python", runtime.python)
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
        if (stack.failed or stack.keep_requested) and self.keep and self.kept is None:
            self.kept = stack
            path = self.evidence.save_password(stack.password)
            print(f"\nkept stack {stack.project}; admin password in {path}")
            return
        stack.down()


def _deliver_helpers(
    stack: Stack, manager: StackManager, splunk: tuple[str, ...]
) -> None:
    """Certificates and target code copied in, then the target is started.

    Splunk containers get the CA at /tmp/wptest-ca.pem (SSL_CERT_FILE in the
    standalone stack) and the CA and client certificate files in SPLUNK_CERT_DIR.
    """
    for service in splunk:
        stack.cp(manager.certificates.ca, service, "/tmp/wptest-ca.pem")
        stack.exec(service, f"mkdir -p {SPLUNK_CERT_DIR}\n", user="root")
        for path in manager.certificates.splunk_files:
            stack.cp(path, service, f"{SPLUNK_CERT_DIR}/{path.name}")
        stack.exec(
            service,
            f"chown -R splunk:splunk {SPLUNK_CERT_DIR}\n"
            f"chmod 0644 {SPLUNK_CERT_DIR}/ca.pem {SPLUNK_CERT_DIR}/client.pem\n"
            f"chmod 0600 {SPLUNK_CERT_DIR}/client.key"
            f" {SPLUNK_CERT_DIR}/client-combined.pem\n",
            user="root",
        )
    if "target" not in stack.compose("config", "--services").split():
        return
    stack.exec("target", "mkdir -p /srv/certs\n", user="root")
    stack.cp(INTEGRATION / "target" / "server.py", "target", "/srv/server.py")
    for path in [manager.certificates.ca, *manager.certificates.server_files]:
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
        helpers = stack.probe_helpers(service)
        results[service] = {
            **{f"{h}:{p}": c for (h, p), c in result.classes.items()},
            **helpers.codes,
        }
        problems += result.problems() + helpers.problems()
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


def _config_archive(manager: StackManager, app: str, runtime: Runtime) -> Path:
    """The config app for app, with the interpreter override runtime needs."""
    return install.build_config_app(
        APPS_DIR / app,
        manager.workdir / f"website_ping_inputs-{app}-{runtime.id}.tar.gz",
        extra=install.python_override(runtime),
    )


def setup_standalone(stack: Stack, manager: StackManager) -> None:
    _start(stack, manager)
    _deliver_helpers(stack, manager, ("so1",))
    _probe(stack, manager, ("so1",))
    install.install_single(
        stack,
        "so1",
        manager.package,
        _config_archive(manager, "standalone", stack.runtime),
        True,
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
        stack,
        "so1",
        manager.package,
        _config_archive(manager, "no_route", stack.runtime),
        True,
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


def setup_distributed(stack: Stack, manager: StackManager) -> None:
    _start(stack, manager)
    _deliver_helpers(stack, manager, stack.splunk_services)
    _probe(stack, manager, stack.splunk_services)
    stack.facts.update(
        install.install_distributed(
            stack,
            manager.package,
            _config_archive(manager, "distributed", stack.runtime),
        )
    )
    install.wait_registered(stack, "hf", "dist-check", stack.stages)
    wait_for(
        STARTED,
        lambda: True if stack.target_log() else None,
        EVENT_TIMEOUT,
        stack.stages,
    )


def setup_spike(stack: Stack, manager: StackManager) -> None:
    """Standalone compose file with only the probe app installed."""
    _start(stack, manager)
    _deliver_helpers(stack, manager, ("so1",))
    _probe(stack, manager, ("so1",))
    stack.cp(
        install.build_probe_app(manager.workdir), "so1", install.PROBE_IN_CONTAINER
    )
    install.install_app(stack, "so1", install.PROBE_IN_CONTAINER)
    install.stop_mark_start(stack, "so1", mark_from_target=False)
    stack.stages.reached(INSTALL)


def setup_golden(stack: Stack, manager: StackManager) -> None:
    """Standalone compose file with Website Monitoring 2.9.7 instead of website-ping.

    Passwords go into storage/passwords before the inputs exist and the config
    files go into website_monitoring/local/, so the first check already sees
    both. The old app reads its configuration at start (single instance), so
    the restart after copying is the one that applies it.
    """
    source = legacy.download()
    package = legacy.build_legacy_package(
        source, manager.workdir / f"{legacy.LEGACY_APP}-{legacy.LEGACY_VERSION}.tar.gz"
    )
    _start(stack, manager)
    _deliver_helpers(stack, manager, ("so1",))
    _probe(stack, manager, ("so1",))
    legacy.install_legacy(stack, "so1", package)
    rest = stack.rest("so1")
    app = wait_for(
        "legacy app visible",
        lambda: rest.app(legacy.LEGACY_APP) or None,
        install.RESTART_TIMEOUT,
        stack.stages,
    )
    manager.evidence.note(
        f"{stack.project}.legacy",
        {
            "commit": legacy.LEGACY_COMMIT,
            "source_sha256": legacy.sha256(source),
            "package_sha256": legacy.sha256(package),
            "version": app.get("version"),
        },
    )
    for realm, username, password in parity.passwords():
        rest.post(
            f"/servicesNS/nobody/{legacy.LEGACY_APP}/storage/passwords",
            {"name": username, "password": password, "realm": realm},
        )
    inputs = manager.workdir / "golden-inputs.conf"
    inputs.write_text(parity.inputs_conf(), encoding="utf-8")
    conf = manager.workdir / "golden-website_monitoring.conf"
    conf.write_text(parity.website_monitoring_conf(), encoding="utf-8")
    legacy.write_local(
        stack, "so1", {"inputs.conf": inputs, "website_monitoring.conf": conf}
    )
    install.stop_mark_start(stack, "so1", mark_from_target=True)
    stack.stages.reached(INSTALL)
    install.wait_registered(stack, "so1", "status-200", stack.stages)


SETUPS: dict[str, Callable[[Stack, StackManager], None]] = {
    "standalone": setup_standalone,
    "noroute": setup_noroute,
    "distributed": setup_distributed,
    "spike": setup_spike,
    "golden": setup_golden,
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
    lines = sorted({runtime.line for runtime in selected_runtimes(request.config)})
    violations = run_preflight(lines, workdir)
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
def standalone(stacks: StackManager, runtime: Runtime) -> Stack:
    return stacks.get(runtime, "standalone")


@pytest.fixture
def no_route_stack(stacks: StackManager, runtime: Runtime) -> Stack:
    return stacks.get(runtime, "noroute")


@pytest.fixture
def distributed_stack(stacks: StackManager, runtime: Runtime) -> Stack:
    return stacks.get(runtime, "distributed")


@pytest.fixture
def spike_stack(stacks: StackManager, runtime: Runtime) -> Stack:
    return stacks.get(runtime, "spike")


@pytest.fixture
def golden_stack(stacks: StackManager, runtime: Runtime) -> Stack:
    if runtime.line != legacy.LEGACY_LINE:
        pytest.skip(
            f"Website Monitoring 2.9.7 is captured on {legacy.LEGACY_LINE} only"
        )
    return stacks.get(runtime, "golden")


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
