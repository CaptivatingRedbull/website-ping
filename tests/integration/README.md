# website-ping integration tests

These tests install the built website-ping package into Splunk Enterprise
9.4.17 and 10.6.1.1 running in Docker, let Splunk run the input, and check the
events that reach the index. The design is in
`docs/designs/website-ping-test-harness.md`.

A bare `pytest` never runs them. They run only when a command-line path names
`tests/integration`.

## Requirements

* Docker Engine and the Compose plugin, installed as described in
  `docker-setup.md`, including the firewall rule. Docker's data root must be
  `/data/docker`.
* Membership of the `docker` group. In a shell started before you joined it,
  run commands as `sg docker -c '<command>'`.
* The images `splunk/splunk:9.4.17` and `splunk/splunk:10.6.1.1`, plus
  `python:3.13.18-slim` and `ubuntu/squid:6.6-24.04_edge`. Missing images are
  pulled on first use.
* At least 200 GB free on `/data`, and available memory of the stack's limits
  plus 4 GB: about 6.5 GB for the standalone stack and 13.25 GB for the
  distributed one.
* The test requirements: `pip install -r requirements-test.txt`.

## Splunk's terms

Setting `WPTEST_ACCEPT_SPLUNK_TERMS=yes` accepts Splunk's license and Splunk
General Terms for the test containers. Without it, the session stops before
any container starts.

## Commands

```sh
export WPTEST_ACCEPT_SPLUNK_TERMS=yes
pytest tests/integration -m "single or network"   # standalone stack, both lines
pytest tests/integration -m no_route               # no-route stack
pytest tests/integration -m distributed            # distributed stack
pytest tests/integration -m release                # AppInspect on the tarball
pytest tests/integration -m spike --splunk-line 9.4 -k standalone --keep
pytest tests/integration                           # everything, one stack at a time
```

Options:

* `--splunk-line 9.4`, `--splunk-line 10.6` or `--splunk-line all` (default).
* `--keep` keeps the first failing stack running and stops the session. Its
  admin password is in `tests/integration/.evidence/<run>/password`, readable
  only by you. Remove kept stacks with `scripts/test-clean.sh`.

A standalone stack takes about 7 minutes per line, the no-route stack about
2 minutes and the distributed stack about 10 minutes.

## Isolation rules

The main Splunk on this host must not be disturbed. The session enforces this:

* **Config preflight.** Before any build or container start, every compose
  file (plus any named in `WPTEST_EXTRA_COMPOSE`) is rendered and compared with
  an allowed list. A fixed host port, `privileged`, host networking, bind
  mounts, a missing memory or CPU limit, a missing label or any setting not on
  the list stops the session. Test stanza URLs may name only `target`,
  `wptest.invalid` and `192.0.2.10`.
* **Host snapshot.** The main `splunkd` process ID, start time and the
  listeners on ports 8000, 8088, 8089 and 9997 are recorded at the start and
  compared at the end. Any difference fails the session.
* **Probe.** Before installing anything, each Splunk container must reach the
  target, be refused on a closed port, and be blocked from the host's ports:
  filtered by the firewall rule, or unreachable on the no-route stack.
* **Resource gate.** Before each stack, free disk and available memory are
  checked again.
* **One session at a time.** `tests/integration/.evidence/run.lock` is held for
  the whole session.
* Only objects labelled `website-ping.test=true` are created or removed.

## Reading a failing run

Each run writes `tests/integration/.evidence/<run>/record.json`: image IDs,
tarball SHA-256, whether the working tree had uncommitted changes, the
interpreter the input used, the probe results and the fields each scenario
differed on. A failed stack also saves `splunkd.log`, container logs, target
and Squid logs and the last search result in a folder named after the stack,
with the admin password and its base64 forms removed.

A failure names the stage that failed, and the last stage reached: build,
healthy, probe, install, input registered, script started, event indexed,
event visible on the search head. A failure before "event indexed" is a
harness or environment problem first. After it, compare with
`expected_failures.md`: a listed scenario must fail on its listed field, and
any other failure is new.

Labelled stacks left by a killed session are reported at the start of the
next session. Remove them with `scripts/test-clean.sh`.
