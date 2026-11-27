"""Build dist/<id>-<version>[-<flavor>].tar.gz, ready for AppInspect or installing in Splunk.

Two flavors come from the same source tree:

* drop-in (default): replaces Website Monitoring and keeps its names.
* side-by-side: runs on an instance where Website Monitoring stays installed. The
  scheme, the default input stanza and the conf file get the app's own name
  (website_ping), and no knowledge object is shared with other apps. See
  docs/side-by-side.md.

The side-by-side flavor rewrites a few files while packaging. Every rewrite expects
its source text exactly; when the text has changed, the build stops instead of
shipping a half-renamed app.
"""

from __future__ import annotations

import argparse
import configparser
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).absolute().parent.parent
APP_ITEMS = (
    "LICENSE",
    "NOTICE",
    "README.md",
    "README",
    "bin",
    "default",
    "lookups",
    "metadata",
    "static",
)
EXCLUDED_NAMES = {"__pycache__", ".DS_Store"}
EXCLUDED_SUFFIXES = {".pyc", ".orig", ".swp"}
EXECUTABLES = {"bin/web_ping.py"}
"""Source paths of files that get mode 755, also when the package renames them."""
DROP_IN = "drop-in"
SIDE_BY_SIDE = "side-by-side"
FLAVORS = (DROP_IN, SIDE_BY_SIDE)
REPOSITORY = "https://github.com/CaptivatingRedbull/website-ping"


class RewriteError(SystemExit):
    """A source file no longer contains the text a rewrite expects."""


@dataclass(frozen=True)
class Swap:
    """Replace old by new: exactly count times, or every time (at least once) if
    count is None."""

    old: str
    new: str
    count: int | None = 1


@dataclass(frozen=True)
class Rewrite:
    """Ship source (relative to the repository) as target, with swaps applied."""

    source: str
    target: str
    swaps: tuple[Swap, ...]


def apply_swaps(name: str, text: str, swaps: tuple[Swap, ...]) -> str:
    for swap in swaps:
        found = text.count(swap.old)
        if swap.count is None:
            if found == 0:
                raise RewriteError(f"{name}: {swap.old!r} not found")
        elif found != swap.count:
            raise RewriteError(
                f"{name}: {swap.old!r} found {found} times, expected {swap.count}"
            )
        text = text.replace(swap.old, swap.new)
    return text


def side_by_side_rewrites(version: str) -> tuple[Rewrite, ...]:
    """What the side-by-side flavor changes, relative to the drop-in files."""
    scheme = Swap("web_ping://", "website_ping://", None)
    conf_file = Swap("website_monitoring.conf", "website_ping.conf", None)
    doc = f"{REPOSITORY}/blob/v{version}/docs/side-by-side.md"
    return (
        Rewrite(
            "bin/wp_names.py",
            "bin/wp_names.py",
            (
                Swap('CONF_NAME = "website_monitoring"', 'CONF_NAME = "website_ping"'),
                Swap('FLAVOR = "drop-in"', 'FLAVOR = "side-by-side"'),
            ),
        ),
        Rewrite("bin/web_ping.py", "bin/website_ping.py", ()),
        Rewrite(
            "README/inputs.conf.spec", "README/inputs.conf.spec", (scheme, conf_file)
        ),
        Rewrite(
            "README/website_monitoring.conf.spec",
            "README/website_ping.conf.spec",
            (
                conf_file,
                Swap("settings for web_ping\n", "settings for website_ping\n"),
            ),
        ),
        Rewrite(
            "default/website_monitoring.conf",
            "default/website_ping.conf",
            (conf_file,),
        ),
        Rewrite(
            "default/inputs.conf",
            "default/inputs.conf",
            (Swap("[web_ping]\n", "[website_ping]\n"),),
        ),
        Rewrite(
            "default/app.conf",
            "default/app.conf",
            (
                Swap("label = Website Ping\n", "label = Website Ping (side-by-side)\n"),
                Swap(
                    "description = A Splunk app for monitoring websites.\n",
                    "description = A Splunk app for monitoring websites."
                    " Side-by-side build, runs next to Website Monitoring.\n",
                ),
                conf_file,
                Swap("reload.website_monitoring = ", "reload.website_ping = "),
            ),
        ),
        Rewrite(
            "default/props.conf",
            "default/props.conf",
            (
                Swap("[source::web_ping://...]\n", "[source::website_ping://...]\n"),
                scheme,
            ),
        ),
        Rewrite(
            "metadata/default.meta",
            "metadata/default.meta",
            (
                Swap(
                    "# Every object is shared with all apps (export = system): searches,"
                    " alerts and\n"
                    "# dashboards written for Website Monitoring call these macros, the"
                    " lookup, the\n"
                    "# eventtype and the tag from whatever app they live in.\n",
                    "# Side-by-side build: no object is shared with other apps"
                    " (export = none).\n"
                    "# Website Monitoring, installed on the same instance, keeps the"
                    " global names;\n"
                    "# these objects work inside the website_ping app.\n",
                ),
                Swap("export = system\n", "export = none\n", None),
            ),
        ),
        Rewrite(
            "README.md",
            "README.md",
            (
                Swap(
                    "(App ID: `website_ping`)\n",
                    "(App ID: `website_ping`)\n\n"
                    "> **Side-by-side build.** This package runs on an instance where"
                    " Website\n"
                    "> Monitoring stays installed. Its names differ from the ones in"
                    " this README:\n"
                    "> inputs are `[website_ping://<name>]`, their defaults"
                    " `[website_ping]`, the\n"
                    "> settings file is `website_ping.conf`, and the macros, eventtype,"
                    " tag,\n"
                    "> lookup, saved searches and views are not shared with other"
                    " apps. Read\n"
                    f"> [docs/side-by-side.md]({doc}).\n",
                ),
            ),
        ),
    )


def read_app_conf() -> tuple[str, str]:
    """Return (package id, version) from default/app.conf."""
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(ROOT / "default" / "app.conf", encoding="utf-8")
    return (
        parser.get("package", "id").strip(),
        parser.get("launcher", "version").strip(),
    )


def check_app_items() -> None:
    """Stop with a clear message when an app item is missing (e.g. on a fresh clone)."""
    for item in APP_ITEMS:
        if not (ROOT / item).exists():
            raise SystemExit(f"missing app item: {item}")


def normalize(info: tarfile.TarInfo, source: str) -> tarfile.TarInfo:
    """Owner and mode as the package ships them; source is the repository path."""
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o755 if info.isdir() or source in EXECUTABLES else 0o644
    return info


def build(flavor: str = DROP_IN) -> Path:
    if flavor not in FLAVORS:
        raise SystemExit(f"unknown flavor: {flavor}")
    check_app_items()
    app_id, version = read_app_conf()
    rewrites = side_by_side_rewrites(version) if flavor == SIDE_BY_SIDE else ()
    rewritten = {rewrite.source for rewrite in rewrites}
    # Read and check every rewrite before writing anything.
    contents = [
        apply_swaps(
            rewrite.source,
            (ROOT / rewrite.source).read_text(encoding="utf-8"),
            rewrite.swaps,
        ).encode("utf-8")
        for rewrite in rewrites
    ]

    def clean(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        path = PurePosixPath(info.name)
        if EXCLUDED_NAMES.intersection(path.parts) or path.suffix in EXCLUDED_SUFFIXES:
            return None
        relative = path.relative_to(app_id).as_posix()
        if relative in rewritten:
            return None
        return normalize(info, relative)

    suffix = "" if flavor == DROP_IN else f"-{flavor}"
    target = ROOT / "dist" / f"{app_id}-{version}{suffix}.tar.gz"
    target.parent.mkdir(exist_ok=True)
    with tarfile.open(target, "w:gz") as tar:
        for item in APP_ITEMS:
            tar.add(ROOT / item, arcname=f"{app_id}/{item}", filter=clean)
        for rewrite, data in zip(rewrites, contents):
            info = tar.gettarinfo(ROOT / rewrite.source, f"{app_id}/{rewrite.target}")
            info.size = len(data)
            tar.addfile(normalize(info, rewrite.source), io.BytesIO(data))
    return target


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build the app package.")
    _ = parser.add_argument("--flavor", choices=FLAVORS, default=DROP_IN)
    args = parser.parse_args(argv)
    print(build(args.flavor))


if __name__ == "__main__":
    main()
