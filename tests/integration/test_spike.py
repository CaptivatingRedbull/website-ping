"""The single-instance probe. Runs only with -m spike.

The tests assert only that probe events arrive.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from wptest.evidence import Evidence
from wptest.install import (
    DEPLOYMENT_APPS,
    PROBE_APP,
    PROBE_IN_CONTAINER,
    build_probe_app,
    restart,
)
from wptest.stack import SPLUNK, Stack
from wptest.wait import wait_for

pytestmark = pytest.mark.spike

EVENT_TIMEOUT = 300
SOURCES = frozenset({"wp_probe://units", "wp_probe://seconds"})
EVIDENCE_SCRIPT = f"""\
echo '--- PROBE and wp_probe lines in splunkd.log'
grep -h -e PROBE -e wp_probe /opt/splunk/var/log/splunk/splunkd.log || true
echo '--- btool inputs list wp_probe --debug'
{SPLUNK} btool inputs list wp_probe --debug || true
echo '--- modinputs folder'
ls -la /opt/splunk/var/lib/splunk/modinputs/ 2>&1 || true
echo '--- probe processes'
ps -eo pid,ppid,lstart,args | grep -e '[w]p_probe' || true
"""
SERVERCLASS_APPEND = """\
cat >> /opt/splunk/etc/system/local/serverclass.conf <<'EOF'

[serverClass:wptest_probe]
whitelist.0 = hf
restartSplunkd = false
stateOnClient = enabled

[serverClass:wptest_probe:app:wptest_probe]
EOF
"""


def probe_query(since: float) -> str:
    return (
        f'search index=* source="wp_probe://*" _index_earliest={int(since)}'
        " | stats count latest(_raw) as raw by source index sourcetype host"
    )


def wait_for_probe_events(stack: Stack, service: str) -> list[dict[str, str]]:
    searcher = stack.searcher(service)

    def both_stanzas() -> list[dict[str, str]] | None:
        rows = searcher.search(probe_query(stack.mark))
        return rows if SOURCES <= {row["source"] for row in rows} else None

    return wait_for(
        "probe events", both_stanzas, EVENT_TIMEOUT, stack.stages, interval=10
    )


def save_evidence(
    stack: Stack, service: str, rows: list[dict[str, str]], evidence: Evidence
) -> None:
    evidence.note(f"{stack.project}.probe_events", rows)
    evidence.save(
        stack.project,
        f"{service}-probe.txt",
        stack.exec(service, EVIDENCE_SCRIPT),
        stack.password,
    )


def test_probe_events_standalone(spike_stack: Stack, evidence: Evidence) -> None:
    spike_stack.keep_requested = True
    rows = wait_for_probe_events(spike_stack, "so1")
    save_evidence(spike_stack, "so1", rows, evidence)
    assert SOURCES <= {row["source"] for row in rows}


@pytest.mark.distributed
def test_probe_deployed(
    distributed_stack: Stack, tmp_path: Path, evidence: Evidence
) -> None:
    """Question 6, deployment server push: the probe goes to the forwarder
    with restartSplunkd = false, so a later push shows whether splunkd
    restarts the script without a restart of its own."""
    stack = distributed_stack
    stack.keep_requested = True
    stack.cp(build_probe_app(tmp_path), "ds", PROBE_IN_CONTAINER)
    stack.exec("ds", f"set -e\ntar -xzf {PROBE_IN_CONTAINER} -C {DEPLOYMENT_APPS}\n")
    stack.exec("ds", SERVERCLASS_APPEND)
    stack.splunk("ds", "reload deploy-server")
    wait_for(
        "probe delivered",
        lambda: (
            True
            if PROBE_APP in stack.exec("hf", "ls /opt/splunk/etc/apps\n").split()
            else None
        ),
        300,
        stack.stages,
    )
    restart(stack, "hf")
    rows = wait_for_probe_events(stack, "sh")
    save_evidence(stack, "hf", rows, evidence)
    assert SOURCES <= {row["source"] for row in rows}
