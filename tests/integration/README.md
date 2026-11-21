# website-ping integration tests

These tests install the built website-ping package into every supported
Splunk Enterprise line (9.4, 10.0, 10.2, 10.4 and 10.6, pinned in `LINES` in
`wptest/versions.py`) running in Docker, let Splunk run the input, and check
the events that reach the index. 9.4 and 10.0 run the input on Python 3.9;
10.2, 10.4 and 10.6 ship 3.13 and 3.9 and run it on either. The design is in
`docs/designs/website-ping-test-harness.md`.

A bare `pytest` never runs them. They run only when a command-line path names
`tests/integration`.

## Requirements

* Docker Engine and the Compose plugin, installed as described in
  `docker-setup.md`, including the firewall rule. Docker's data root must be
  `/data/docker`.
* Membership of the `docker` group. In a shell started before you joined it,
  run commands as `sg docker -c '<command>'`.
* The Splunk images of the lines under test (`splunk/splunk:9.4.17`,
  `10.0.12`, `10.2.9`, `10.4.5` and `10.6.1.1`), plus `python:3.13.18-slim`
  and `ubuntu/squid:6.6-24.04_edge`. Missing images are pulled on first use.
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
pytest tests/integration -m "single or network or parity"   # standalone and parity stacks, oldest and newest line
pytest tests/integration -m "single or network or parity" --splunk-line all --python all   # every runtime (release)
pytest tests/integration -m parity                 # parity stack only
pytest tests/integration -m no_route               # no-route stack
pytest tests/integration -m distributed            # distributed stack
pytest tests/integration -m release                # AppInspect on the tarball
pytest tests/integration -m spike --splunk-line 9.4 -k standalone --keep
pytest tests/integration -m golden --splunk-line 9.4 --golden-write    
pytest tests/integration -m migration --splunk-line all --python all   # migration from Website Monitoring 2.9.7 (release)
pytest tests/integration                           # everything, one stack at a time
```

Options:

* `--splunk-line` takes a line (`9.4`, `10.0`, `10.2`, `10.4`, `10.6`), a
  comma-separated list of lines (`--splunk-line 10.0,10.2`), `edges` (default:
  the oldest and the newest line, 9.4 and 10.6) or `all`. An unknown line
  stops the session before collection.
* `--keep` keeps the first failing stack running and stops the session. A
  parity run that includes `test_view_searches.py` keeps its stack even when
  nothing fails, so the views can be opened in Splunk Web: `docker port
  <stack>-so1-1 8000` names the port on 127.0.0.1. The admin password is in
  `tests/integration/.evidence/<run>/password`, readable only by you. Remove
  kept stacks with `scripts/test-clean.sh`.
* `--python 3.9`, `--python 3.13` or `--python all` picks the interpreter on
  lines that ship several (10.2, 10.4, 10.6). Without it, such a line runs
  3.13, which the app's own `python.required` selects. For 3.9 the config app
  gets `local/inputs.conf` with `[web_ping] python.required = 3.9`. 9.4 and
  10.0 always run 3.9. The probe (`spike`) and Website Monitoring 2.9.7
  (`golden`) choose their own interpreter, so they run only on each line's
  default. Test ids and stack names carry the runtime, for example
  `[10.6-py3.9]` and `wptest-106-py39-standalone-<id>`.

A standalone stack takes about 7 minutes per runtime, the no-route stack about
2 minutes and the distributed stack about 10 minutes. `--splunk-line all
--python all` has 8 runtimes.
The parity stack (`-m parity`) runs website-ping with the scenarios of
`wptest/parity.py` and compares each newest check event with the golden event
of Website Monitoring 2.9.7 in `tests/golden/2.9.7/` (`wptest/golden.py`,
allowed differences in `ALLOWED_DIFFERENCES`). Scenarios in `parity.PENDING`
need a feature website-ping does not have yet: they are skipped with that
feature as the reason and left out of the stack's config. Scenarios in
`parity.REFUSED` are refused by website-ping on purpose: they stay in the
config and the test expects their ERROR in `website_ping.log`, no event and no
request. Scenarios in `parity.INTENDED` differ from 2.9.7 on purpose in a way the
event comparison cannot express (`ntlm-offered`: an event with the site's 401,
where 2.9.7 wrote none); they stay in the config and have their own test. For
the scenarios in `parity.REQUESTS_COMPARED` the target's request log is compared
with the fixture as well (`golden.compare_requests`, allowed differences in
`REQUEST_ALLOWED`): header names and order, the authentication scheme of each
request and the client certificate's name, so the number of requests per check
must equal 2.9.7's.

The migration stack (`-m migration`, run only when `-m` names it) follows
`docs/migration.md`. On 9.4 it installs Website Monitoring 2.9.7 with the
configuration of `wptest/migration.py` and
`migration/website_monitoring_local/` (plain-text passwords, a user name and
password in a URL, overridden macros, eventtype and alert, a saved search of
its own, an input in the `search` app), applies "Changes to make before the
migration", and migrates with the guide's own shell blocks. Which files are
copied is read from the guide's tables under "Files to copy". The tests check
the old app's checkpoints carried over, events against the golden fixtures,
the copied overrides, the alert and its Log Event action, every view search,
the alert `Website Ping Runner Silent` after `kill -STOP` of the runner, and the
guide's rollback. On the other lines 2.9.7 does not install: a fresh stack gets
the same files in the place of the guide's backup, the passwords are stored
again, and the same tests run without the checkpoint, rollback and 2.9.7 ones.
The `kill -STOP` test runs on 9.4 and on 10.6 with 3.13 only. The migration
stack takes about 18 minutes on 9.4, 11 of them for the `kill -STOP` test.

The parity stack stores every password in `storage/passwords` (in the `search`
app) before the inputs start; its generated `inputs.conf` and
`website_monitoring.conf` contain none. `test_no_credential_in_any_log_or_event`
then searches the Splunk instance's log folder, the input's checkpoints, the
files of website-ping and its config app, the container logs of the target,
Squid and Splunk, and every indexed `web_ping` event for each test password
(as written, percent-encoded and as a Basic token). It never runs a Splunk
search for a password, so its own search history cannot match. The result is
in `record.json` under `<stack>.credential-scan`, with labels instead of the
passwords.

## Isolation rules

The main Splunk on this host must not be disturbed. The session enforces this:

* **Config preflight.** Before any build or container start, every compose
  file (plus any named in `WPTEST_EXTRA_COMPOSE`) is rendered and compared with
  an allowed list. A fixed host port, `privileged`, host networking, bind
  mounts, a missing memory or CPU limit, a missing label or any setting not on
  the list stops the session. Test stanza URLs may name only `target`,
  `env-proxied` (an alias of the target), `wptest.invalid` and `192.0.2.10`.
* **Host snapshot.** The main `splunkd` process ID, start time and the
  listeners on ports 8000, 8088, 8089 and 9997 are recorded at the start and
  compared at the end. Any difference fails the session.
* **Probe.** Before installing anything, each Splunk container must reach the
  target, be refused on a closed port, and be blocked from the host's ports:
  filtered by the firewall rule, or unreachable on the no-route stack. It must
  also pass the mTLS port 8447 with the client certificate (split and combined
  files) and be refused without it, and, where Squid runs, get through 3128,
  through 3129 with the proxy user, and a 407 from 3129 without it.
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
