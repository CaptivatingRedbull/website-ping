"""Golden events of Website Monitoring 2.9.7. Runs only with -m golden, on 9.4.

With --golden-write the capture is written to tests/golden/2.9.7/; without it a
fresh capture is compared with the stored fixtures, to show the capture is stable.
"""

from __future__ import annotations

import json
import time
import warnings
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
from wptest import golden, legacy, parity
from wptest.evidence import Evidence
from wptest.install import ROOT
from wptest.splunk_rest import Searcher
from wptest.stack import Stack
from wptest.versions import LINES

pytestmark = pytest.mark.golden

GOLDEN_DIR = ROOT / "tests" / "golden" / legacy.LEGACY_VERSION
META = "_capture.json"
CAPTURE_TIMEOUT = 600
POLL_INTERVAL = 10
COUNT_QUERY = (
    'search index=main sourcetype=web_ping source="web_ping://*"'
    " _index_earliest={since} | stats count by source"
)
LEGACY_LOG = "/opt/splunk/var/log/splunk/web_availability_modular_input.log"
README = """\
# Golden events: Website Monitoring {version}

Captured by `tests/integration/test_golden.py` (commit 04). One JSON file per
scenario of `tests/integration/wptest/parity.py`: the normalised events
(`wptest/golden.py`), the target's request log lines and Squid's log lines for
the first `min_events` checks. `{meta}` has the details of the capture.

* Website Monitoring {version}, commit `{commit}`, built from the GitHub tag
  (`wptest/legacy.py`), installed in `website_monitoring` with the config in
  `local/`, as in production.
* Splunk image `{image}`, digest `{digest}`.
* Captured {date}.
* Incomplete scenarios (fewer events than `min_events`): {incomplete}.

Re-capture:

```sh
export WPTEST_ACCEPT_SPLUNK_TERMS=yes
pytest tests/integration -m golden --splunk-line 9.4 --golden-write
pytest tests/integration -m golden --splunk-line 9.4   # must pass: the capture is stable
```

Normalised: `total_time` and `request_time` to `{number}`, volatile response
headers to `{volatile}`, `_time` to `{time}` when splunkd assigned it on
arrival. Hashes, sizes and `host` are kept as captured.
"""


def check_counts(searcher: Searcher, since: float) -> dict[str, int]:
    rows = searcher.search(COUNT_QUERY.format(since=int(since)))
    return {
        row["source"].removeprefix("web_ping://"): int(row["count"]) for row in rows
    }


def missing(counts: dict[str, int]) -> list[str]:
    return [
        s.title
        for s in parity.PARITY_SCENARIOS
        if counts.get(s.title, 0) < s.min_events
    ]


def wait_for_checks(stack: Stack) -> dict[str, int]:
    """Poll until every scenario has min_events checks, or CAPTURE_TIMEOUT passed."""
    searcher = stack.searcher("so1")
    deadline = time.monotonic() + CAPTURE_TIMEOUT
    while True:
        counts = check_counts(searcher, stack.mark)
        if not missing(counts) or time.monotonic() >= deadline:
            stack.stages.reached("golden events")
            return counts
        time.sleep(POLL_INTERVAL)


def squid_log(stack: Stack) -> list[tuple[float, golden.ProxyRequest]]:
    parsed = (
        golden.parse_squid_line(line) for line in stack.logs("squid").splitlines()
    )
    return [entry for entry in parsed if entry is not None]


def capture(stack: Stack, evidence: Evidence) -> dict[str, golden.Capture]:
    counts = wait_for_checks(stack)
    searcher = stack.searcher("so1")
    searcher.search(golden.export_query(stack.mark))
    export = searcher.last_result
    rows: dict[str, list[dict[str, golden.FieldValue]]] = defaultdict(list)
    for row in golden.parse_export(export):
        source = row.get("source", "")
        if isinstance(source, str):
            rows[source.removeprefix("web_ping://")].append(row)
    target_log = stack.target_log()
    proxied = squid_log(stack)
    save = evidence.save
    save(stack.project, "golden-export.jsonl", export, stack.password)
    save(
        stack.project,
        "golden-counts.json",
        json.dumps(counts, indent=2),
        stack.password,
    )
    save(stack.project, "target.log", stack.logs("target"), stack.password)
    save(stack.project, "squid.log", stack.logs("squid"), stack.password)
    save(
        stack.project,
        "web_availability_modular_input.log",
        stack.exec("so1", f"cat {LEGACY_LOG} 2>&1 || true\n"),
        stack.password,
    )
    return {
        s.title: golden.select_capture(
            s,
            sorted(rows.get(s.title, []), key=golden.event_time),
            target_log,
            proxied,
            stack.mark,
        )
        for s in parity.PARITY_SCENARIOS
    }


def write_fixtures(
    stack: Stack, captures: dict[str, golden.Capture], folder: Path
) -> list[str]:
    for path in folder.glob("*.json"):
        path.unlink()
    for item in captures.values():
        golden.write_capture(folder, item)
    incomplete = sorted(title for title, item in captures.items() if not item.complete)
    line = LINES[legacy.LEGACY_LINE]
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    meta = {
        "legacy_version": legacy.LEGACY_VERSION,
        "legacy_commit": legacy.LEGACY_COMMIT,
        "legacy_source_sha256": legacy.LEGACY_SHA256,
        "image": line.image,
        "digest": line.digest,
        "captured": date,
        "incomplete": incomplete,
        "input_environment": stack.input_process("so1"),
    }
    (folder / META).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    (folder / "README.md").write_text(
        README.format(
            version=legacy.LEGACY_VERSION,
            commit=legacy.LEGACY_COMMIT,
            meta=META,
            image=line.image,
            digest=line.digest,
            date=date,
            incomplete=", ".join(f"`{t}`" for t in incomplete) or "none",
            number=golden.NUMBER,
            volatile=golden.VOLATILE,
            time=golden.TIME,
        )
    )
    return incomplete


def test_golden_capture(
    golden_stack: Stack, request: pytest.FixtureRequest, evidence: Evidence
) -> None:
    captures = capture(golden_stack, evidence)
    if request.config.getoption("--golden-write"):
        for title in write_fixtures(golden_stack, captures, GOLDEN_DIR):
            warnings.warn(f"golden capture incomplete for {title}", stacklevel=1)
        return
    problems: list[str] = []
    for title, fresh in captures.items():
        diffs = golden.compare_capture(golden.read_capture(GOLDEN_DIR, title), fresh)
        evidence.note(f"{golden_stack.project}.golden.{title}", [str(d) for d in diffs])
        problems += [f"{title}: {diff}" for diff in diffs]
    if problems:
        pytest.fail(
            "fresh capture differs from the fixtures:\n" + "\n".join(problems),
            pytrace=False,
        )
