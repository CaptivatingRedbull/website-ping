"""Read results from Splunk: REST on a loopback port, or the CLI through exec."""

from __future__ import annotations

import base64
import json
import shlex
import ssl
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Protocol, cast


def _flatten(result: dict[str, object]) -> dict[str, str]:
    """Search results as strings. A multivalue field keeps its first value."""
    flat: dict[str, str] = {}
    for key, value in result.items():
        if isinstance(value, list):
            values = cast("list[object]", value)
            value = values[0] if values else ""
        flat[key] = str(value)
    return flat


def parse_results(text: str) -> list[dict[str, str]]:
    """Parse JSON search output: one object per line, or one document."""
    results: list[dict[str, str]] = []
    text = text.strip()
    if not text:
        return results
    try:
        documents: list[object] = [json.loads(text)]
    except json.JSONDecodeError:
        documents = [json.loads(line) for line in text.splitlines() if line.strip()]
    for document in documents:
        entry = cast("dict[str, object]", document)
        if isinstance(entry.get("results"), list):
            for item in cast("list[dict[str, object]]", entry["results"]):
                results.append(_flatten(item))
        elif isinstance(entry.get("result"), dict):
            results.append(_flatten(cast("dict[str, object]", entry["result"])))
    return results


EVENT_FIELDS = (
    "wptest_time title url response_code total_time timed_out error"
    " sourcetype index source host _raw"
)


def events_query(title: str, since: float, extra: str = "") -> str:
    """Events of one stanza indexed since the mark, newest first."""
    return (
        f'search index=main sourcetype=website-ping title="{title}"'
        f" _index_earliest={int(since)} {extra}"
        f" | eval wptest_time=_time | table {EVENT_FIELDS}"
    )


class Searcher(Protocol):
    last_result: str

    def search(self, query: str) -> list[dict[str, str]]: ...


class SplunkRest:
    """Splunk's REST API on 127.0.0.1. Its management certificate is self-signed."""

    def __init__(self, port: int, password: str) -> None:
        self.base = f"https://127.0.0.1:{port}"
        token = base64.b64encode(f"admin:{password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}"}
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        self.last_result = ""

    def _call(self, path: str, data: dict[str, str] | None = None) -> str:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(
            self.base + path, data=body, headers=self._headers
        )
        with self._opener.open(request, timeout=120) as response:
            return cast(bytes, response.read()).decode()

    def get(self, path: str) -> dict[str, object]:
        separator = "&" if "?" in path else "?"
        text = self._call(f"{path}{separator}output_mode=json&count=0")
        return cast("dict[str, object]", json.loads(text))

    def post(self, path: str, data: dict[str, str]) -> dict[str, object]:
        """POST form data; the response as JSON."""
        separator = "&" if "?" in path else "?"
        text = self._call(f"{path}{separator}output_mode=json", data)
        return cast("dict[str, object]", json.loads(text))

    def search(self, query: str) -> list[dict[str, str]]:
        """The query starts with "search", which the REST API needs."""
        self.last_result = self._call(
            "/services/search/jobs/export",
            {
                "search": query,
                "output_mode": "json",
                "earliest_time": "0",
                "preview": "false",
            },
        )
        return parse_results(self.last_result)

    def app(self, name: str) -> dict[str, object]:
        entry = cast(
            "list[dict[str, object]]", self.get(f"/services/apps/local/{name}")["entry"]
        )
        return cast("dict[str, object]", entry[0]["content"])


class SplunkCli:
    """The Splunk CLI through docker compose exec, for a stack with no published port.

    The CLI adds "search" itself, so a leading "search" is removed from the query.
    """

    def __init__(self, run: Callable[[str], str]) -> None:
        self._run = run
        self.last_result = ""

    def search(self, query: str) -> list[dict[str, str]]:
        query = query.strip()
        query = query.removeprefix("search ")
        self.last_result = self._run(
            "/opt/splunk/bin/splunk search "
            f"{shlex.quote(query)} -output json -maxout 0 -earliest_time 0"
        )
        return parse_results(self.last_result)
