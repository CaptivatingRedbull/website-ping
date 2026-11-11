"""Build the packages and install them per role, then verify what Splunk installed."""

from __future__ import annotations

import configparser
import hashlib
import io
import subprocess
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

from wptest.stack import SPLUNK, Stack
from wptest.wait import Stages, wait_for

ROOT = Path(__file__).absolute().parents[3]
APP = "website-ping"
CONFIG_APP = "website_ping_inputs"
APPS_DIR = ROOT / "tests" / "integration" / "apps"
TARBALL_IN_CONTAINER = "/tmp/website-ping.tar.gz"
CONFIG_IN_CONTAINER = "/tmp/website_ping_inputs.tar.gz"
EXECUTABLE = "bin/web_ping.py"
EXTRA_ALLOWED = ("bin/__pycache__/", "local/")
RESTART_TIMEOUT = 300
# splunk install app records the archive's checksum in default/app.conf and
# metadata/local.meta. A deployment client records the app's state in
# local/app.conf and metadata/local.meta instead. Measured on both lines.
APP_CONF = "default/app.conf"
INSTALL_CHECKSUM = ("install", "install_source_checksum")
LOCAL_META = "metadata/local.meta"
INSTALLED_STANZAS = ["app/install/install_source_checksum"]
DEPLOYED_STANZAS = ["app/install/state"]


@dataclass(frozen=True)
class Package:
    path: Path
    sha256: str
    version: str
    dirty: bool
    files: dict[str, str]
    """SHA-256 of every file in the tarball, by path relative to the app folder."""
    folders: frozenset[str]
    app_conf: str
    """default/app.conf as it is in the tarball."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse(text: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(text)
    return parser


def _settings(text: str) -> dict[tuple[str, str], str]:
    parser = _parse(text)
    return {
        (section, key): value.strip()
        for section in parser.sections()
        for key, value in parser.items(section)
    }


def _launcher_version(text: str) -> str:
    return _parse(text).get("launcher", "version").strip()


def app_conf_differences(packaged: str, installed: str) -> list[str]:
    """Settings that differ, ignoring the checksum splunk install app adds."""
    expected = _settings(packaged)
    actual = _settings(installed)
    actual.pop(INSTALL_CHECKSUM, None)
    return [
        f"[{section}] {key}: {expected.get((section, key))!r} -> {actual.get((section, key))!r}"
        for section, key in sorted(expected.keys() | actual.keys())
        if expected.get((section, key)) != actual.get((section, key))
    ]


def build_package() -> Package:
    """Run scripts/package.py and record the tarball's hash and the working tree state."""
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "package.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    path = Path(output.strip())
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    files: dict[str, str] = {}
    folders: set[str] = set()
    app_conf = ""
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            relative = member.name.split("/", 1)[1] if "/" in member.name else ""
            if member.isdir() and relative:
                folders.add(relative)
            elif member.isfile():
                extracted = tar.extractfile(member)
                assert extracted is not None
                data = extracted.read()
                files[relative] = _sha256(data)
                if relative == APP_CONF:
                    app_conf = data.decode()
    return Package(
        path,
        _sha256(path.read_bytes()),
        _launcher_version(app_conf),
        dirty,
        files,
        frozenset(folders),
        app_conf,
    )


def build_config_app(source: Path, output: Path) -> Path:
    """Archive a config app: top folder website_ping_inputs, uid 0, 644 files, 755 folders."""
    with tarfile.open(output, "w:gz") as tar:
        paths = sorted(source.rglob("*"))
        for path in [source, *paths]:
            relative = path.relative_to(source).as_posix()
            name = CONFIG_APP if relative == "." else f"{CONFIG_APP}/{relative}"
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mtime = int(time.time())
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            else:
                data = path.read_bytes()
                info.mode = 0o644
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    output.chmod(0o644)
    return output


def install_app(stack: Stack, service: str, archive: str) -> None:
    """splunk install app. A non-zero exit raises with the output kept."""
    stack.splunk(service, f"install app {archive}")


def copy_package(stack: Stack, service: str, package: Package) -> None:
    package.path.chmod(0o644)
    stack.cp(package.path, service, TARBALL_IN_CONTAINER)


def splunk_running(stack: Stack, service: str) -> bool:
    try:
        output = stack.splunk(service, "status", timeout=120)
    except Exception:  # noqa: BLE001 - "not running" exits non-zero
        return False
    return "splunkd is running" in output


def stop_mark_start(stack: Stack, service: str, mark_from_target: bool) -> float:
    """Stop Splunk, mark the target log, start Splunk. Returns the mark time."""
    stack.splunk(service, "stop", timeout=RESTART_TIMEOUT)
    mark = time.time()
    if mark_from_target:
        stack.exec(service, "curl --noproxy '*' -fsS http://target:8080/__reset\n")
    stack.splunk(service, "start --answer-yes --no-prompt", timeout=RESTART_TIMEOUT)
    wait_for(
        f"splunk running on {service}",
        lambda: True if splunk_running(stack, service) else None,
        RESTART_TIMEOUT,
        stack.stages,
    )
    stack.mark = mark
    return mark


INSPECT_SCRIPT = """\
set -e
cd {path}
find . -mindepth 1 -printf '%y\\t%P\\t%m\\t%u\\n'
echo '--- hashes'
find . -type f -exec sha256sum {{}} +
"""


@dataclass(frozen=True)
class Installed:
    kind: str
    """"f" for a file, "d" for a folder, as find prints it."""
    mode: str
    owner: str
    sha256: str


def installed_files(stack: Stack, service: str, path: str) -> dict[str, Installed]:
    """Every entry of an installed app, by path relative to the app folder."""
    output = stack.exec(service, INSPECT_SCRIPT.format(path=path))
    listing, _, hashes = output.partition("--- hashes\n")
    digests: dict[str, str] = {}
    for line in hashes.splitlines():
        if line.strip():
            digest, name = line.split(None, 1)
            digests[name.strip().removeprefix("./")] = digest
    entries: dict[str, Installed] = {}
    for line in listing.splitlines():
        kind, relative, mode, owner = line.split("\t")
        entries[relative] = Installed(kind, mode, owner, digests.get(relative, ""))
    return entries


def verify_install(
    stack: Stack,
    service: str,
    package: Package,
    path: str = f"/opt/splunk/etc/apps/{APP}",
    deployed: bool = False,
) -> list[str]:
    """Version, hashes, mode and owner, as under "Installing the apps".

    splunk install app adds install_source_checksum to default/app.conf and
    creates metadata/local.meta for it. So app.conf is compared setting by
    setting without that key, and local.meta may hold only the stanza its
    install route writes. deployed means delivered by the deployment server,
    which writes a different stanza and leaves out the empty static folder.
    """
    stanzas_expected = DEPLOYED_STANZAS if deployed else INSTALLED_STANZAS
    problems: list[str] = []
    entries = installed_files(stack, service, path)
    installed_app_conf = stack.exec(service, f"cat {path}/{APP_CONF}\n")
    for relative, digest in package.files.items():
        if relative not in entries:
            problems.append(f"{service}: {relative} missing")
            continue
        entry = entries[relative]
        if relative == APP_CONF:
            problems += [
                f"{service}: {APP_CONF} {difference}"
                for difference in app_conf_differences(
                    package.app_conf, installed_app_conf
                )
            ]
        elif entry.sha256 != digest:
            problems.append(f"{service}: {relative} has a different SHA-256")
        if entry.owner != "splunk":
            problems.append(f"{service}: {relative} owned by {entry.owner}")
        if relative == EXECUTABLE and entry.mode != "755":
            problems.append(
                f"{service}: {relative} has mode {entry.mode}, expected 755"
            )
    for folder in package.folders:
        if folder not in entries and not (deployed and folder == "static"):
            problems.append(f"{service}: folder {folder} missing")
    for relative, entry in entries.items():
        known = relative in package.files or relative in package.folders
        allowed = any((relative + "/").startswith(prefix) for prefix in EXTRA_ALLOWED)
        if relative == LOCAL_META and relative not in package.files:
            stanzas = _parse(stack.exec(service, f"cat {path}/{LOCAL_META}\n"))
            if stanzas.sections() != stanzas_expected:
                problems.append(
                    f"{service}: {LOCAL_META} has stanzas {stanzas.sections()},"
                    f" expected only {stanzas_expected}"
                )
        elif not known and not allowed:
            kind = "folder" if entry.kind == "d" else "file"
            problems.append(f"{service}: unexpected {kind} {relative}")
    version = _launcher_version(installed_app_conf)
    if version != package.version:
        problems.append(f"{service}: version {version}, expected {package.version}")
    return problems


def script_mode(stack: Stack, service: str, path: str) -> str:
    return stack.exec(service, f"stat -c %a {path}/{EXECUTABLE}\n").strip()


def install_single(
    stack: Stack,
    service: str,
    package: Package,
    config_archive: Path,
    mark_from_target: bool,
) -> float:
    """Single instance: both apps by splunk install app, then stop, mark, start."""
    copy_package(stack, service, package)
    stack.cp(config_archive, service, CONFIG_IN_CONTAINER)
    install_app(stack, service, TARBALL_IN_CONTAINER)
    install_app(stack, service, CONFIG_IN_CONTAINER)
    mark = stop_mark_start(stack, service, mark_from_target)
    problems = verify_install(stack, service, package)
    if problems:
        raise stack.stages.fail("install", "; ".join(problems))
    stack.stages.reached("install")
    return mark


def stanza_registered(stack: Stack, service: str, stanza: str) -> bool:
    output = stack.exec(service, f"{SPLUNK} btool inputs list web_ping://{stanza}\n")
    return f"[web_ping://{stanza}]" in output


def wait_registered(stack: Stack, service: str, stanza: str, stages: Stages) -> None:
    wait_for(
        "input registered",
        lambda: True if stanza_registered(stack, service, stanza) else None,
        RESTART_TIMEOUT,
        stages,
    )


DEPLOYMENT_APPS = "/opt/splunk/etc/deployment-apps"
SERVERCLASS = APPS_DIR / "deployment_server" / "serverclass.conf"
DEPLOYMENT_TIMEOUT = 300
PHONE_HOME_SCRIPT = """\
set -e
conf=/opt/splunk/etc/system/local/deploymentclient.conf
if grep -q '^\\[deployment-client\\]' "$conf"; then
  sed -i '/^\\[deployment-client\\]/a phoneHomeIntervalInSecs = 15' "$conf"
else
  printf '\\n[deployment-client]\\nphoneHomeIntervalInSecs = 15\\n' >> "$conf"
fi
"""


def restart(stack: Stack, service: str) -> None:
    """splunk stop, then start. Success is judged by splunk status."""
    stack.splunk(service, "stop", timeout=RESTART_TIMEOUT)
    stack.splunk(service, "start --answer-yes --no-prompt", timeout=RESTART_TIMEOUT)
    wait_running(stack, service)


def wait_running(stack: Stack, service: str) -> None:
    wait_for(
        f"splunk running on {service}",
        lambda: True if splunk_running(stack, service) else None,
        RESTART_TIMEOUT,
        stack.stages,
    )


def apps_present(stack: Stack, service: str) -> list[str]:
    output = stack.exec(service, "ls /opt/splunk/etc/apps\n")
    return sorted(name for name in output.split() if name in (APP, CONFIG_APP))


def install_distributed(
    stack: Stack, package: Package, config_archive: Path
) -> dict[str, object]:
    """Indexer and search head by splunk install app, the forwarder from the
    deployment server. Returns what the tests check about delivery."""
    facts: dict[str, object] = {}
    problems: list[str] = []
    for service in ("idx", "sh"):
        copy_package(stack, service, package)
        install_app(stack, service, TARBALL_IN_CONTAINER)
        restart(stack, service)
        problems += verify_install(stack, service, package)

    stack.exec("hf", PHONE_HOME_SCRIPT)
    restart(stack, "hf")
    facts["hf_apps_before_checkin"] = apps_present(stack, "hf")

    copy_package(stack, "ds", package)
    stack.cp(config_archive, "ds", CONFIG_IN_CONTAINER)
    stack.exec(
        "ds",
        f"set -e\ntar -xzf {TARBALL_IN_CONTAINER} -C {DEPLOYMENT_APPS}\n"
        f"tar -xzf {CONFIG_IN_CONTAINER} -C {DEPLOYMENT_APPS}\n",
    )
    facts["ds_script_mode"] = script_mode(stack, "ds", f"{DEPLOYMENT_APPS}/{APP}")
    stack.cp(SERVERCLASS, "ds", "/opt/splunk/etc/system/local/serverclass.conf")
    stack.exec(
        "ds",
        "chown splunk:splunk /opt/splunk/etc/system/local/serverclass.conf\n",
        user="root",
    )
    stack.splunk("ds", "reload deploy-server")

    wait_for(
        "deployment delivery",
        lambda: (
            True if apps_present(stack, "hf") == sorted([APP, CONFIG_APP]) else None
        ),
        DEPLOYMENT_TIMEOUT,
        stack.stages,
    )
    # restartSplunkd = true restarts the forwarder after delivery. Let it finish.
    wait_running(stack, "hf")
    time.sleep(30)
    wait_running(stack, "hf")
    stop_mark_start(stack, "hf", mark_from_target=True)
    problems += verify_install(stack, "hf", package, deployed=True)
    facts["hf_local"] = stack.exec(
        "hf", f"ls /opt/splunk/etc/apps/{APP}/local 2>/dev/null || true\n"
    ).split()
    if problems:
        raise stack.stages.fail("install", "; ".join(problems))
    stack.stages.reached("install")
    return facts
