"""The dashboards are Simple XML 1.1 without custom code, keep Website
Monitoring's view names, and read the data the app writes."""

from __future__ import annotations

import configparser
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).absolute().parent.parent
VIEWS = ROOT / "default" / "data" / "ui" / "views"
NAV = ROOT / "default" / "data" / "ui" / "nav" / "default.xml"

VIEW_NAMES = {
    "status_overview",
    "status_history",
    "site_changes",
    "exec_summary",
    "web_ping_logs",
    "web_ping_status",
}
"""Website Monitoring's views that are rebuilt, under the same names."""
BUILT_IN_VIEWS = {"search", "datasets", "reports", "alerts", "dashboards"}
EVENTS = 'sourcetype="web_ping" `website_monitoring_search_index`'
LOG = 'index=_internal sourcetype="website_ping:log"'
HEALTH_VIEWS = {"web_ping_logs", "web_ping_status"}
APP_LINK = re.compile(r"/app/website_ping/(\w+)")


def view_paths() -> list[Path]:
    return sorted(VIEWS.glob("*.xml"))


def root_of(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def standalone_queries(root: ET.Element) -> list[str]:
    """Queries of searches that are not post-processes of a base search."""
    queries: list[str] = []
    for search in root.iter("search"):
        query = search.find("query")
        if search.get("base") is None and query is not None and query.text:
            queries.append(query.text.strip())
    return queries


def test_the_views_are_website_monitorings_views() -> None:
    assert {path.stem for path in view_paths()} == VIEW_NAMES
    assert not [p.name for p in VIEWS.iterdir() if p.suffix != ".xml"]


@pytest.mark.parametrize("path", view_paths(), ids=lambda p: p.stem)
def test_view_is_simple_xml_1_1_without_custom_code(path: Path) -> None:
    root = root_of(path)
    assert root.tag in ("form", "dashboard")
    assert root.get("version") == "1.1"
    for element in root.iter():
        assert element.tag != "script", path.name
        assert not {"script", "stylesheet"} & set(element.attrib), (
            path.name,
            element.tag,
        )
    for html in root.iter("html"):
        text = ET.tostring(html, encoding="unicode").lower()
        assert "<script" not in text
        assert not re.search(r"\son\w+\s*=", text), "inline event handler"


@pytest.mark.parametrize("path", view_paths(), ids=lambda p: p.stem)
def test_every_search_reads_the_apps_events_or_its_log(path: Path) -> None:
    """Event searches go through the index macro, so a local override of
    website_monitoring_search_index applies; only the health views read the
    input's log in _internal."""
    for query in standalone_queries(root_of(path)):
        if query.startswith(EVENTS):
            continue
        assert path.stem in HEALTH_VIEWS, query
        assert query.startswith(LOG), query


@pytest.mark.parametrize("path", view_paths(), ids=lambda p: p.stem)
def test_every_post_process_names_a_base_search_of_its_view(path: Path) -> None:
    root = root_of(path)
    ids = {s.get("id") for s in root.iter("search") if s.get("id")}
    for search in root.iter("search"):
        base = search.get("base")
        if base is not None:
            assert base in ids, base


@pytest.mark.parametrize("path", view_paths(), ids=lambda p: p.stem)
def test_links_to_the_app_name_its_views(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for name in APP_LINK.findall(text):
        assert name in VIEW_NAMES | BUILT_IN_VIEWS, name


def test_nav_lists_every_view_with_status_overview_as_default() -> None:
    nav = ET.parse(NAV).getroot()
    views = [element.get("name") for element in nav.iter("view")]
    assert set(views) == VIEW_NAMES | BUILT_IN_VIEWS
    assert len(views) == len(set(views))
    defaults = [e.get("name") for e in nav.iter("view") if e.get("default")]
    assert defaults == ["status_overview"]
    health = next(c for c in nav.iter("collection") if c.get("label") == "Health")
    assert [e.get("name") for e in health.iter("view")] == sorted(HEALTH_VIEWS)


def test_app_is_visible() -> None:
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",)
    )
    _ = parser.read(ROOT / "default" / "app.conf", encoding="utf-8")
    assert parser.get("ui", "is_visible") == "true"
