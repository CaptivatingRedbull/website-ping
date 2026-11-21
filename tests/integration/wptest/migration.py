"""The configuration of a Website Monitoring 2.9.7 installation to migrate, and the
file rules of docs/migration.md that the migration test follows.

The inputs are parity scenarios, so their events can be compared with the golden
fixtures, at production-style intervals. Each file exists twice: as an admin
would have it before the migration (plain-text passwords included) and after the
guide's "Changes to make before the migration".

Which files are copied into website_ping is not listed here: it is read from the
tables under "Files to copy" in docs/migration.md, so the test does what the
guide says and fails when the guide stops making sense.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from target.server import AUTH_PASSWORD, AUTH_USER

from wptest.install import ROOT
from wptest.parity import (
    CONF_STANZAS,
    PROXY_REALM,
    PROXY_USERNAME,
    ParityScenario,
    by_title,
)
from wptest.stack import INTEGRATION, PROXY_PASSWORD, TARGET_PORT

GUIDE = ROOT / "docs" / "migration.md"
STATIC_LOCAL = INTEGRATION / "migration" / "website_monitoring_local"
"""Hand-written files of the old app, by path relative to its folder."""

LEGACY_APP = "website_monitoring"
SEARCH_APP = "search"

URL_CREDENTIALS = ParityScenario(
    "url-credentials",
    f"http://{AUTH_USER}:{AUTH_PASSWORD}@target:{TARGET_PORT}/auth/basic/url-credentials",
)
"""User name and password in the URL, which 2.9.7 sent as Basic credentials.
No golden fixture: the parity capture has no such row."""


@dataclass(frozen=True)
class LegacyInput:
    """One [web_ping://<title>] stanza of the old installation."""

    scenario: ParityScenario
    interval: str
    app: str = LEGACY_APP
    """The app whose local/inputs.conf holds the stanza. An input created in
    Splunk Web lands in the app selected at the time, often search."""

    @property
    def title(self) -> str:
        return self.scenario.title

    @property
    def stanza(self) -> str:
        return f"web_ping://{self.title}"

    @property
    def seconds(self) -> int:
        """The interval in seconds (units s, m, h or none)."""
        match = re.fullmatch(r"(\d+)([smh]?)", self.interval)
        if match is None:
            raise ValueError(f"{self.stanza}: interval {self.interval!r}")
        return int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]

    def settings(self, *, changed: bool) -> dict[str, str]:
        """The stanza's settings. changed: after the plain-text password was
        stored and removed, and the URL's user moved into username."""
        values = self.scenario.stanza()
        values["interval"] = self.interval
        if not changed:
            return values
        values.pop("password", None)
        if self.scenario is URL_CREDENTIALS:
            values["url"] = without_userinfo(values["url"])
            values["username"] = AUTH_USER
        return values


def _legacy(title: str, interval: str, app: str = LEGACY_APP) -> LegacyInput:
    return LegacyInput(by_title()[title], interval, app)


LEGACY_INPUTS: tuple[LegacyInput, ...] = (
    _legacy("status-200", "1m"),
    _legacy("status-503", "1m"),
    _legacy("refused", "1m"),
    _legacy("timeout", "1m"),
    _legacy("match-no", "1m"),
    _legacy("basic-plain", "1m"),
    _legacy("basic-secure", "1m"),
    _legacy("proxy-auth", "1m"),
    LegacyInput(URL_CREDENTIALS, "1m"),
    _legacy("status-404", "1m", SEARCH_APP),
    _legacy("proxy-plain", "5m"),
    _legacy("headers", "5m"),
    _legacy("tls-valid", "10m"),
    _legacy("body-small", "15m"),
    _legacy("thresholds", "15m"),
    _legacy("redirect-302", "1h"),
)
"""Every input of the old installation. The 1m inputs give events within a
minute of each start; the longer intervals keep their schedule across the
migration, and the 10m input is due again only after website_ping has started."""

CONF_DEFAULT: Mapping[str, str] = {
    "thread_limit": "20",
    "max_response_body_length": "1000",
}
CONF_NAMED = ("plain", "auth", "ignore")
"""website_monitoring.conf stanzas besides [default]; ignore is named by no input."""


@dataclass(frozen=True)
class StoredPassword:
    app: str
    """The app whose storage/passwords endpoint the entry is created in."""
    realm: str
    username: str
    password: str


PRESTORED: tuple[StoredPassword, ...] = (
    StoredPassword(LEGACY_APP, "web_ping://basic-secure", AUTH_USER, AUTH_PASSWORD),
)
"""Stored by 2.9.7's input page, so kept in website_monitoring/local/passwords.conf."""

MOVED_TO_STORE: tuple[StoredPassword, ...] = (
    StoredPassword(SEARCH_APP, "web_ping://basic-plain", AUTH_USER, AUTH_PASSWORD),
    StoredPassword(SEARCH_APP, "web_ping://url-credentials", AUTH_USER, AUTH_PASSWORD),
    StoredPassword(SEARCH_APP, PROXY_REALM, PROXY_USERNAME, PROXY_PASSWORD),
)
"""The plain-text passwords, stored in search as the guide recommends."""

NEW_HOST_PASSWORDS: tuple[StoredPassword, ...] = (
    *(replace(p, app=SEARCH_APP) for p in PRESTORED),
    *MOVED_TO_STORE,
)
"""On another host passwords.conf cannot be decrypted; the guide says to store
the passwords again there, which puts them in search."""

PLAIN_SECRETS = (AUTH_PASSWORD, PROXY_PASSWORD)
"""Passwords that must never be found in plain text in website_ping's files."""


def without_userinfo(url: str) -> str:
    scheme, separator, rest = url.partition("://")
    authority, slash, path = rest.partition("/")
    return f"{scheme}{separator}{authority.rpartition('@')[2]}{slash}{path}"


def inputs_in(app: str) -> tuple[LegacyInput, ...]:
    return tuple(i for i in LEGACY_INPUTS if i.app == app)


def _stanza_text(name: str, values: Mapping[str, str]) -> str:
    for key, value in values.items():
        if "\n" in value or "\r" in value or value != value.strip():
            raise ValueError(f"[{name}] {key}: value cannot be written to a .conf file")
    return f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in values.items())


def inputs_conf(*, changed: bool) -> str:
    """website_monitoring/local/inputs.conf."""
    return "\n".join(
        _stanza_text(i.stanza, i.settings(changed=changed))
        for i in inputs_in(LEGACY_APP)
    )


def website_monitoring_conf(*, changed: bool) -> str:
    """website_monitoring/local/website_monitoring.conf. changed: without the
    plain-text proxy password."""
    stanzas = [_stanza_text("default", CONF_DEFAULT)]
    for name in CONF_NAMED:
        values = dict(CONF_STANZAS[name])
        if changed:
            values.pop("proxy_password", None)
        stanzas.append(_stanza_text(name, values))
    return "\n".join(stanzas)


def static_files(folder: Path = STATIC_LOCAL) -> dict[str, str]:
    """The hand-written files, by path relative to the app folder."""
    return {
        path.relative_to(folder).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    }


def legacy_files(*, changed: bool) -> dict[str, str]:
    """Every file written into website_monitoring/, by path relative to it."""
    files = static_files()
    generated = {
        "local/inputs.conf": inputs_conf(changed=changed),
        "local/website_monitoring.conf": website_monitoring_conf(changed=changed),
    }
    clash = sorted(files.keys() & generated.keys())
    if clash:
        raise ValueError(f"written by hand and generated: {clash}")
    return {**files, **generated}


# ---- the guide's file tables ------------------------------------------------

_CODE = re.compile(r"`([^`]+)`")
COPY_HEADER = "| File | What to do |"
KEEP_OUT_HEADER = "| File | Why |"
VIEWS_DIR = "local/data/ui/views"


@dataclass(frozen=True)
class CopyRule:
    """A row of the "Files to copy" table."""

    pattern: str
    """Relative to the app folder; * matches within one path segment."""
    merge: bool
    """Merge stanzas into the file of the same name instead of copying."""
    skip: tuple[str, ...] = ()
    """File names the row says to leave out although the pattern matches."""


@dataclass(frozen=True)
class FileRules:
    copy: tuple[CopyRule, ...]
    keep_out: tuple[str, ...]
    """Patterns of the "Do not copy" table; one ending in / is a folder."""


@dataclass(frozen=True)
class CopyPlan:
    copy: tuple[str, ...]
    merge: tuple[str, ...]
    left: tuple[str, ...]
    """Files of the old app that no rule copies or merges."""


def section(text: str, heading: str) -> str:
    """The text under a heading, up to the next heading of the same or a higher
    level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    start = lines.index(heading) + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if re.match(rf"#{{1,{level}}} ", lines[index])
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def table_rows(text: str, header: str) -> list[tuple[str, str]]:
    """(first cell, second cell) of each row of the table whose header line is
    header. Raises ValueError when there is no such table or it has no row."""
    lines = text.splitlines()
    if header not in lines:
        raise ValueError(f"no table {header!r}")
    rows: list[tuple[str, str]] = []
    for line in lines[lines.index(header) + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2:
            raise ValueError(f"expected two cells: {line!r}")
        rows.append((cells[0], cells[1]))
    if not rows:
        raise ValueError(f"table {header!r} has no rows")
    return rows


def matches(pattern: str, relative: str) -> bool:
    if pattern.endswith("/"):
        return relative.startswith(pattern)
    same_depth = len(PurePosixPath(pattern).parts) == len(PurePosixPath(relative).parts)
    return same_depth and fnmatch.fnmatchcase(relative, pattern)


def _copy_rule_rows(rows: Sequence[tuple[str, str]]) -> list[CopyRule]:
    rules: list[CopyRule] = []
    for file_cell, action in rows:
        patterns = _CODE.findall(file_cell)
        if not patterns:
            raise ValueError(f"no file in {file_cell!r}")
        for pattern in patterns:
            name = PurePosixPath(pattern).name
            skip = tuple(
                code
                for code in _CODE.findall(action)
                if "/" not in code and code != name and fnmatch.fnmatchcase(code, name)
            )
            rules.append(CopyRule(pattern, action.startswith("Merge"), skip))
    return rules


def _keep_out_rows(rows: Sequence[tuple[str, str]]) -> list[str]:
    patterns: list[str] = []
    for file_cell, _ in rows:
        codes = _CODE.findall(file_cell)
        if file_cell.startswith("Views "):
            patterns += [f"{VIEWS_DIR}/{name}.xml" for name in codes]
        elif codes and all("/" in code for code in codes):
            patterns += codes
        else:
            raise ValueError(f"cannot read {file_cell!r}")
    return patterns


def file_rules(text: str) -> FileRules:
    """The rules of the "Files to copy" section of the migration guide."""
    part = section(text, "## Files to copy")
    return FileRules(
        tuple(_copy_rule_rows(table_rows(part, COPY_HEADER))),
        tuple(_keep_out_rows(table_rows(part, KEEP_OUT_HEADER))),
    )


def read_file_rules(path: Path = GUIDE) -> FileRules:
    return file_rules(path.read_text(encoding="utf-8"))


def plan_copies(files: Iterable[str], rules: FileRules) -> CopyPlan:
    """What to do with each file of the old app (paths relative to its folder).

    Raises ValueError for a file that a copy rule and a "Do not copy" row both
    name: the guide would contradict itself.
    """
    copy: list[str] = []
    merge: list[str] = []
    left: list[str] = []
    for relative in sorted(files):
        rule = next(
            (
                r
                for r in rules.copy
                if matches(r.pattern, relative)
                and PurePosixPath(relative).name not in r.skip
            ),
            None,
        )
        kept_out = [p for p in rules.keep_out if matches(p, relative)]
        if rule is not None and kept_out:
            raise ValueError(
                f"{relative}: copied by {rule.pattern}, kept out by {kept_out}"
            )
        if rule is None:
            left.append(relative)
        elif rule.merge:
            merge.append(relative)
        else:
            copy.append(relative)
    return CopyPlan(tuple(copy), tuple(merge), tuple(left))


# ---- metadata ---------------------------------------------------------------

_STANZA = re.compile(r"^\s*\[(?P<name>[^\]]*)\]\s*$")


def stanza_blocks(text: str) -> list[tuple[str, str]]:
    """(name, text) of each stanza, header line included. Lines before the first
    stanza are left out; a .meta file Splunk writes has none."""
    blocks: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        match = _STANZA.match(line)
        if match:
            blocks.append((match["name"], [line]))
        elif blocks:
            blocks[-1][1].append(line)
    return [(name, "\n".join(lines).rstrip() + "\n") for name, lines in blocks]


def merge_meta(existing: str | None, old: str) -> str:
    """existing with every stanza of old it does not have yet appended. A stanza
    that both have keeps existing's text."""
    have = {name for name, _ in stanza_blocks(existing or "")}
    added = [block for name, block in stanza_blocks(old) if name not in have]
    parts = [existing.rstrip() + "\n"] if existing and existing.strip() else []
    return "\n".join(parts + added)


# ---- the guide's commands and searches --------------------------------------

_FENCE = re.compile(
    r"^```(?P<language>\S*)\n(?P<body>.*?)^```$", re.MULTILINE | re.DOTALL
)
STANDALONE_STEPS = "### Standalone instance or heavy forwarder"
AFTER_THE_START = "### After the start"
ROLLBACK = "## Rollback"
PACKAGE_PLACEHOLDER = "website_ping-<version>.tar.gz"
_START = re.compile(r"^(?P<command>\S*bin/splunk start)[ \t]*$", re.MULTILINE)
_KEY = re.compile(r"[a-z][a-z_.]*")


def code_blocks(text: str, language: str) -> list[str]:
    """The bodies of the fenced blocks of one language ("" for none)."""
    return [
        match["body"]
        for match in _FENCE.finditer(text)
        if match["language"] == language
    ]


def standalone_steps(guide: str) -> tuple[str, str]:
    """The two shell blocks of the standalone steps: up to the copying of the
    files, and the start after it."""
    blocks = code_blocks(section(guide, STANDALONE_STEPS), "sh")
    if len(blocks) != 2:
        raise ValueError(f"{STANDALONE_STEPS}: expected 2 sh blocks, got {len(blocks)}")
    return blocks[0], blocks[1]


def rollback_steps(guide: str) -> str:
    blocks = code_blocks(section(guide, ROLLBACK), "sh")
    if len(blocks) != 1:
        raise ValueError(f"{ROLLBACK}: expected 1 sh block, got {len(blocks)}")
    return blocks[0]


def rollback_keys(guide: str) -> tuple[str, ...]:
    """The settings the rollback section says to remove: the setting names
    written as code in its first paragraph."""
    paragraph = section(guide, ROLLBACK).strip().split("\n\n", 1)[0]
    keys = tuple(code for code in _CODE.findall(paragraph) if _KEY.fullmatch(code))
    if not keys:
        raise ValueError(f"{ROLLBACK}: no setting named in {paragraph!r}")
    return keys


def after_start_searches(guide: str) -> tuple[str, ...]:
    """The searches the guide runs after the start, one per line."""
    blocks = code_blocks(section(guide, AFTER_THE_START), "")
    if len(blocks) != 1:
        raise ValueError(f"{AFTER_THE_START}: expected 1 block, got {len(blocks)}")
    return tuple(line.strip() for line in blocks[0].splitlines() if line.strip())


def unattended(script: str, package: str | None = None) -> str:
    """A shell block of the guide made to run without a terminal: splunk start
    answers its prompts itself, the package placeholder names the package, and
    the first failing command stops the script."""
    if package is not None:
        if PACKAGE_PLACEHOLDER not in script:
            raise ValueError(f"no {PACKAGE_PLACEHOLDER} in {script!r}")
        script = script.replace(PACKAGE_PLACEHOLDER, package)
    script = _START.sub(r"\g<command> --answer-yes --no-prompt", script)
    return "set -e\n" + script


def without_old_app(script: str) -> str:
    """A shell block of the guide without the lines that name the old app: on a
    host where it was never installed there is nothing to move."""
    kept = [line for line in script.splitlines(keepends=True) if LEGACY_APP not in line]
    if len(kept) == len(script.splitlines()):
        raise ValueError(f"no line names {LEGACY_APP} in {script!r}")
    return "".join(kept)


def remove_keys(text: str, keys: Iterable[str]) -> str:
    """text without the lines that set one of keys in [web_ping] or a
    [web_ping://...] stanza. Every other line stays as it is."""
    remove = set(keys)
    kept: list[str] = []
    in_web_ping = False
    for line in text.splitlines(keepends=True):
        match = _STANZA.match(line)
        if match:
            name = match["name"]
            in_web_ping = name == "web_ping" or name.startswith("web_ping://")
        elif in_web_ping and line.partition("=")[0].strip() in remove and "=" in line:
            continue
        kept.append(line)
    return "".join(kept)


def files_setting(btool_debug: str, keys: Iterable[str]) -> list[str]:
    """Files that set one of keys, from the output of splunk btool ... --debug
    (each line starts with the file the setting comes from)."""
    wanted = set(keys)
    found: set[str] = set()
    for line in btool_debug.splitlines():
        path, _, setting = line.partition(" ")
        if path.startswith("/") and setting.partition("=")[0].strip() in wanted:
            found.add(path)
    return sorted(found)


# ---- checkpoints ------------------------------------------------------------


def checkpoint_name(stanza: str) -> str:
    """The checkpoint file of a stanza, as both apps name it."""
    return hashlib.sha224(stanza.encode("utf-8")).hexdigest() + ".json"


def first_run_window(
    last_run: float, interval: int, started: float, slack: float
) -> tuple[float, float]:
    """When the first check after a start may end: not before the old schedule
    makes the stanza due (last_run + interval) nor before the runner started,
    and at most slack seconds later."""
    earliest = max(last_run + interval, started)
    return earliest, earliest + slack
