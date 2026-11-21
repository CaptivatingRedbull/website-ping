"""The steps of a migration from Website Monitoring 2.9.7 on a test stack: set up
the old installation, apply the guide's changes, migrate and roll back with the
guide's own commands, and read back what happened."""

from __future__ import annotations

import json
import shlex
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

from wptest import golden, install, legacy, migration
from wptest.migration import CopyPlan, FileRules, LegacyInput, StoredPassword
from wptest.splunk_rest import SplunkRest
from wptest.stack import CHECKPOINT_DIR, Stack
from wptest.wait import wait_for

SERVICE = "so1"
SPLUNK_HOME = "/opt/splunk"
APPS = f"{SPLUNK_HOME}/etc/apps"
LEGACY_DIR = f"{APPS}/{legacy.LEGACY_APP}"
APP_DIR = f"{APPS}/{install.APP}"
BACKUP_DIR = f"~/{legacy.LEGACY_APP}-backup/{legacy.LEGACY_APP}"
PACKAGE_DIR = "/tmp"
"""The guide's tar command names the package without a folder: it runs here."""
OVERRIDE_APP_CONF = install.APPS_DIR / "parity" / "default" / "app.conf"
"""app.conf of the app that holds the interpreter override."""
STEP_TIMEOUT = 2 * install.RESTART_TIMEOUT
START_LINE = " starting stanzas="


@dataclass
class Migration:
    """What the setup observed, for the tests to check."""

    legacy_mark: float = 0.0
    """When the old app started with the plain-text configuration."""
    changed_at: float = 0.0
    """When the old app started again after the guide's changes."""
    legacy_events: dict[str, dict[str, golden.FieldValue]] = field(
        default_factory=dict[str, dict[str, golden.FieldValue]]
    )
    """The newest check event of the old app per source, before the migration."""
    checkpoints: dict[str, float | None] = field(
        default_factory=dict[str, Optional[float]]
    )
    """last_run per stanza when Splunk was stopped for the migration."""
    stopped_at: float = 0.0
    started_at: float = 0.0
    """When the guide's start command was run."""
    runner_started: float = 0.0
    """The time of website-ping's start line."""
    rules: FileRules | None = None
    plan: CopyPlan | None = None
    local_meta: str = ""
    """website_ping/metadata/local.meta after the merge."""
    fresh: bool = False
    """A host without Website Monitoring: its files are copied from another one."""


def migration_of(stack: Stack) -> Migration:
    found = stack.facts.get("migration")
    if not isinstance(found, Migration):
        raise TypeError(f"{stack.project}: no migration was set up")
    return found


# ---- files and commands -----------------------------------------------------


def run_guide(stack: Stack, script: str) -> str:
    """A shell block of the guide, run as the splunk user in PACKAGE_DIR."""
    return stack.exec(
        SERVICE,
        f"cd {PACKAGE_DIR}\n{script}",
        env={"SPLUNK_HOME": SPLUNK_HOME, "SPLUNK_USERNAME": "admin"},
        timeout=STEP_TIMEOUT,
    )


def write_files(
    stack: Stack, app_dir: str, files: Mapping[str, str], workdir: Path
) -> None:
    """Text files into an app folder, by path relative to it, owned by splunk.
    .conf files in local/ get mode 600, as Splunk writes them."""
    workdir.mkdir(parents=True, exist_ok=True)
    for relative, text in files.items():
        source = workdir / relative.replace("/", "__")
        source.write_text(text, encoding="utf-8")
        target = f"{app_dir}/{relative}"
        stack.exec(
            SERVICE, f"mkdir -p {shlex.quote(str(PurePosixPath(target).parent))}\n"
        )
        stack.cp(source, SERVICE, target)
    stack.exec(
        SERVICE,
        f"chown -R splunk:splunk {app_dir}\n"
        f"find {app_dir}/local -name '*.conf' -exec chmod 0600 {{}} + 2>/dev/null || true\n",
        user="root",
    )


def home(stack: Stack) -> str:
    """The splunk user's home folder, where the guide keeps the backup."""
    return stack.exec(SERVICE, "printf %s ~\n").strip()


def app_files(stack: Stack, path: str) -> list[str]:
    """Every file below path, relative to it."""
    output = stack.exec(SERVICE, f"cd {path}\nfind . -type f -printf '%P\\n'\n")
    return sorted(line for line in output.splitlines() if line)


def read_file(stack: Stack, path: str) -> str | None:
    """The text of a file in the container, or None when there is none."""
    output = stack.exec(SERVICE, f"if [ -f {path} ]; then echo y; cat {path}; fi\n")
    return output[2:] if output.startswith("y\n") else None


def copy_by_guide(
    stack: Stack, rules: FileRules, workdir: Path
) -> tuple[CopyPlan, str]:
    """Copy and merge what the guide's tables say, from the backup of the old app
    into website_ping. Returns the plan and the merged local.meta."""
    plan = migration.plan_copies(app_files(stack, BACKUP_DIR), rules)
    lines = ["set -e"]
    for relative in plan.copy:
        target = f"{APP_DIR}/{relative}"
        lines.append(f"mkdir -p {shlex.quote(str(PurePosixPath(target).parent))}")
        lines.append(
            f"cp -p {BACKUP_DIR}/{shlex.quote(relative)} {shlex.quote(target)}"
        )
    stack.exec(SERVICE, "\n".join(lines) + "\n")
    merged = ""
    for relative in plan.merge:
        old = read_file(stack, f"{BACKUP_DIR}/{relative}") or ""
        merged = migration.merge_meta(read_file(stack, f"{APP_DIR}/{relative}"), old)
        write_files(stack, APP_DIR, {relative: merged}, workdir)
    return plan, merged


def store_passwords(rest: SplunkRest, entries: Sequence[StoredPassword]) -> None:
    for entry in entries:
        _ = rest.post(
            f"/servicesNS/nobody/{entry.app}/storage/passwords",
            {"name": entry.username, "password": entry.password, "realm": entry.realm},
        )


def create_input(rest: SplunkRest, item: LegacyInput) -> None:
    """The input in its app, created over REST as Splunk Web does."""
    settings = item.settings(changed=True)
    _ = rest.post(
        f"/servicesNS/nobody/{item.app}/data/inputs/web_ping",
        {"name": item.title, **settings},
    )


def read_checkpoints(stack: Stack, stanzas: Iterable[str]) -> dict[str, float | None]:
    """last_run of each stanza's checkpoint file; None when it has none."""
    found: dict[str, float | None] = {}
    for stanza in stanzas:
        text = read_file(stack, f"{CHECKPOINT_DIR}/{migration.checkpoint_name(stanza)}")
        value = json.loads(text).get("last_run") if text else None
        found[stanza] = float(value) if isinstance(value, (int, float)) else None
    return found


def runner_start(stack: Stack, since: float) -> float | None:
    """The time of website-ping's first start line at or after since."""
    return next(
        (
            logged
            for logged, line in stack.app_log(SERVICE)
            if logged >= since and START_LINE in line
        ),
        None,
    )


# ---- events -----------------------------------------------------------------


def check_events(
    stack: Stack, since: float
) -> dict[str, list[dict[str, golden.FieldValue]]]:
    """Check events indexed since since, by source, in arrival order."""
    searcher = stack.searcher(SERVICE)
    searcher.search(golden.export_query(since))
    by_source: dict[str, list[dict[str, golden.FieldValue]]] = {}
    for row in golden.parse_export(searcher.last_result):
        if row.get("sourcetype") == golden.CHECK_SOURCETYPE:
            by_source.setdefault(str(row.get("source")), []).append(row)
    return {
        source: sorted(rows, key=golden.arrival_order)
        for source, rows in by_source.items()
    }


def events_from(
    stack: Stack, since: float, stanzas: Iterable[str]
) -> dict[str, list[dict[str, golden.FieldValue]]] | None:
    """check_events once every stanza has one, else None (for wait_for)."""
    events = check_events(stack, since)
    return events if all(stanza in events for stanza in stanzas) else None


def quick_stanzas() -> list[str]:
    """Stanzas checked every minute: due again after any restart."""
    return [i.stanza for i in migration.LEGACY_INPUTS if i.seconds <= 60]


# ---- the old installation ---------------------------------------------------


def set_up_legacy(stack: Stack, workdir: Path) -> Migration:
    """Website Monitoring 2.9.7 with the plain-text configuration, running until
    every quick stanza has an event; then the guide's changes before the
    migration, and every quick stanza again."""
    state = Migration()
    source = legacy.download()
    package = legacy.build_legacy_package(
        source, workdir / f"{legacy.LEGACY_APP}-{legacy.LEGACY_VERSION}.tar.gz"
    )
    legacy.install_legacy(stack, SERVICE, package)
    rest = stack.rest(SERVICE)
    store_passwords(rest, migration.PRESTORED)
    write_files(
        stack, LEGACY_DIR, migration.legacy_files(changed=False), workdir / "before"
    )
    state.legacy_mark = install.stop_mark_start(stack, SERVICE, mark_from_target=True)
    install.wait_registered(stack, SERVICE, "status-200", stack.stages)
    for item in migration.inputs_in(migration.SEARCH_APP):
        create_input(rest, item)
    _ = wait_for(
        "old app's events",
        lambda: events_from(stack, state.legacy_mark, quick_stanzas()),
        install.RESTART_TIMEOUT,
        stack.stages,
    )

    store_passwords(rest, migration.MOVED_TO_STORE)
    write_files(
        stack, LEGACY_DIR, migration.legacy_files(changed=True), workdir / "after"
    )
    state.changed_at = time.time()
    install.restart(stack, SERVICE)
    events = wait_for(
        "old app's events after the changes",
        lambda: events_from(stack, state.changed_at, quick_stanzas()),
        install.RESTART_TIMEOUT,
        stack.stages,
    )
    state.legacy_events = {source: rows[-1] for source, rows in events.items()}
    return state


def set_up_new_host(
    stack: Stack, workdir: Path, python_override: Mapping[str, str]
) -> Migration:
    """A host that never had Website Monitoring: the old app's files after the
    guide's changes are placed where the guide keeps its backup, and the
    passwords are stored again. python_override, when not empty, goes into an
    app of its own so the input runs on the interpreter under test."""
    state = Migration(fresh=True)
    store_passwords(stack.rest(SERVICE), migration.NEW_HOST_PASSWORDS)
    backup = f"{home(stack)}/{legacy.LEGACY_APP}-backup/{legacy.LEGACY_APP}"
    write_files(stack, backup, migration.legacy_files(changed=True), workdir / "backup")
    if python_override:
        files = {
            "default/app.conf": OVERRIDE_APP_CONF.read_text(encoding="utf-8"),
            **python_override,
        }
        write_files(stack, f"{APPS}/{install.CONFIG_APP}", files, workdir / "python")
    return state


# ---- migration and rollback -------------------------------------------------


def migrate(
    stack: Stack, state: Migration, package: install.Package, workdir: Path
) -> None:
    """The guide's standalone steps: stop, move the old app away, unpack the
    package, copy what the tables say, start. On a fresh host there is no old
    app to move, and the input of the search app is created after the start."""
    guide = migration.GUIDE.read_text(encoding="utf-8")
    before_copy, start = migration.standalone_steps(guide)
    if state.fresh:
        before_copy = migration.without_old_app(before_copy)
    state.rules = migration.file_rules(guide)
    stack.cp(package.path, SERVICE, f"{PACKAGE_DIR}/{package.path.name}")
    stack.exec(SERVICE, f"chmod 0644 {PACKAGE_DIR}/{package.path.name}\n", user="root")
    stanzas = [i.stanza for i in migration.LEGACY_INPUTS]
    state.stopped_at = time.time()
    run_guide(stack, migration.unattended(before_copy, package.path.name))
    state.checkpoints = read_checkpoints(stack, stanzas)
    state.plan, state.local_meta = copy_by_guide(stack, state.rules, workdir / "copied")
    state.started_at = time.time()
    run_guide(stack, migration.unattended(start))
    install.wait_running(stack, SERVICE)
    state.runner_started = wait_for(
        "website-ping started",
        lambda: runner_start(stack, state.started_at),
        install.RESTART_TIMEOUT,
        stack.stages,
    )
    if state.fresh:
        for item in migration.inputs_in(migration.SEARCH_APP):
            create_input(stack.rest(SERVICE), item)


def roll_back(stack: Stack, workdir: Path) -> list[str]:
    """The guide's rollback: remove the settings 2.9.7 does not know from the
    local files that set them (website_ping's own files go away with the app),
    then stop, move website_ping away, move the old app back, start. Returns the
    files that were changed."""
    guide = migration.GUIDE.read_text(encoding="utf-8")
    keys = migration.rollback_keys(guide)
    output = stack.splunk(SERVICE, "btool inputs list web_ping --debug")
    changed = [
        path
        for path in migration.files_setting(output, keys)
        if "/local/" in path and not path.startswith(f"{APP_DIR}/")
    ]
    for number, path in enumerate(changed):
        text = read_file(stack, path) or ""
        source = workdir / f"rollback-{number}.conf"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(migration.remove_keys(text, keys), encoding="utf-8")
        stack.cp(source, SERVICE, path)
        stack.exec(
            SERVICE, f"chown splunk:splunk {path}\nchmod 0600 {path}\n", user="root"
        )
    run_guide(stack, migration.unattended(migration.rollback_steps(guide)))
    install.wait_running(stack, SERVICE)
    return changed
