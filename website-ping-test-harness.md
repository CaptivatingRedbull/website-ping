Superseded by `docs/designs/website-ping-test-harness.md` wherever the two differ.

# website-ping: test harness plan

Nov 9, 2026 · @Marlon

## Goals and scope

The harness proves that website-ping installs, starts and writes correct events on Splunk Enterprise 9.4.x and 10.6.x, standalone and distributed, with and without a proxy in the path, and that none of this touches the Splunk instance already running on this machine.

**In scope**

- Splunk Enterprise only, as official `splunk/splunk` containers, one pinned image tag per version line.
- Single instance, and a distributed topology (heavy forwarder, indexer, search head, deployment server).
- Network behaviour of the HTTP check: proxies, TLS errors, timeouts, redirects, DNS and connection failures.
- Packaging: AppInspect on the built app, once per release.

**Out of scope**

- Splunk Cloud. Testing it needs a cloud stack, which is not available here.
- NTLM and Kerberos proxies (not planned, see the scope doc), and any specific vendor's proxy product.
- Load and scale testing.

A failed check is data, not an error. Every network scenario below therefore asserts on the event that reaches the index, not on a crash or an exit code.

**Tests assert the expected behaviour, never what the code happens to do.** Expected results come from the setting's documented meaning in `README/inputs.conf.spec` and from the scenario tables in this plan. A value the app accepts has to work as documented. If the documentation is silent, the author decides, and the answer is written here before the test exists. When a test fails because the app is wrong, the app is what changes later: the test is not adjusted, skipped or marked as an expected failure to make the run pass.

## Version matrix

Two version lines, each pinned to an exact image tag in one file (`tests/integration/versions.toml`), never `latest`. Bumping a patch release is a one-line change followed by a full run.

| Line | Pin (to confirm) | What the sources say | Why it is in the matrix |
| --- | --- | --- | --- |
| 9.4.x | `splunk/splunk:9.4.10` or newer | 9.4.10 is the tag named in the [May 2026 Splunk Docker advisory](https://advisory.splunk.com/advisories/SVD-2026-0501); a newer 9.4 patch may exist | Oldest line worth supporting; the original app was tested up to 9.4 |
| 10.6.x | `splunk/splunk:10.6.1` or newer | [10.6 was released September 30, 2026](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6); [10.6.1 followed on October 16, 2026](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6/whats-new/whats-new-in-10.6.1) | Target platform of the rewrite |

Three things to check before the first run, because they were not verifiable from the docs:

1. The exact Docker tag spellings on Docker Hub. From 10.6 Splunk [uses a four-segment version (for example 10.6.0.5)](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6), so a patch tag may not look like `10.6.1`. Tests parse the version tolerantly (2 to 4 numeric segments).
2. The Python version each image runs the script with. The harness records `splunk cmd python --version` per line instead of assuming 3.9 on both.
3. License flags. Both lines need `SPLUNK_START_ARGS=--accept-license`; 10.x also needs `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` ([Splunk docs](https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.6/install-splunk-enterprise-in-virtual-and-containerized-environments)).

The 10.x lines between (10.0, 10.2, 10.4) are not tested. Add a row to `versions.toml` if one becomes a customer requirement.

## Isolation from the main Splunk

Every test resource lives under one Compose project name, on a private network, behind loopback-only ephemeral ports, so the Splunk already running on this machine is never reached and never in the way.

| Shared resource | Rule |
| --- | --- |
| Host ports (the main instance uses 8000, 8089, 9997, 8088) | No fixed host ports. Publish only `127.0.0.1::<port>` (random host port); tests read it with `docker compose port`. Nothing binds 0.0.0.0, and `network_mode: host` is never used. |
| Network | One bridge network per project with an explicit subnet from a configurable range, chosen so it does not overlap LAN or VPN ranges. The proxy scenarios add a second network with `internal: true`. |
| Data and volumes | Named volumes only, prefixed with the project name. No bind mounts of host Splunk directories. Teardown is `down -v`. |
| The app files | Only the tarball built by `scripts/package.py` enters a container, copied in with `docker compose cp`. Nothing is bind-mounted, so a container can never write into the repo. |
| Outbound data | The heavy forwarder sends to the indexer's Compose service name. No host IP and no `host.docker.internal` appears in any compose file. |
| Names and cleanup | Project name `wptest-<line>-<topology>-<random>`. Every container, volume and network carries the label `website-ping.test=true`; `scripts/test-clean` removes only objects with that label. |
| CPU and RAM | `mem_limit` and `cpus` on every service. Version lines and topologies run one after another, never in parallel. Starting limits (assumption, to measure on the first run and write back here): 3 GB for the indexer, 2 GB for every other container. |
| Credentials | A random admin password per run, never reused from the main instance. |
| Disk | Docker's data root is `/data/docker`. `/data` also holds the main Splunk's indexes (`SPLUNK_DB=/data/splunk`), and it is mounted without quotas, so per-container disk limits are not available. The preflight aborts the run if `/data` has less than 200 GB free (starting value). |

The preflight runs before any build or container start. It renders the final config with `docker compose config` and fails the whole session if it finds `network_mode: host`, `host.docker.internal`, a published port without `127.0.0.1`, a bind mount outside the repo, `privileged: true`, the Docker socket mounted into a container, host PID or IPC namespaces, or `extra_hosts`. It also fails if `docker info` reports a data root outside `/data/docker`, or if the free-space rule is not met. The isolation rules are checked on every run, not trusted.

## Prerequisite: Docker Engine

The harness uses Docker Engine with Compose v2, not Podman. Docker is not installed on this machine yet, and it runs here next to the main Splunk. Installing it changes the host's firewall rules and routes, and that change is accepted.

1. Before installing, record routes, firewall rules and IP-forwarding settings, and the main `splunkd` process ID and start time.
2. Write `/etc/docker/daemon.json` before Docker first starts. Set `data-root` to `/data/docker`, and set `bip` and `default-address-pools` to ranges that do not overlap the LAN or VPN.
3. Add a systemd drop-in with `RequiresMountsFor=/data`, so Docker cannot start and write to the root disk when `/data` is not mounted.
4. After installing, confirm the main `splunkd` has the same process ID and start time, and keep the before-and-after records.

## Building and installing the app

Every integration session tests the built package, installed the way an administrator installs it. It never tests the working tree.

1. **Build.** Run `scripts/package.py` once at session start and use the path it prints. An existing file in `dist/` is never reused. Record the tarball's SHA-256 and whether the working tree had uncommitted changes.
2. **Copy.** All Splunk services run the unmodified pinned `splunk/splunk` image, with no app files in any image. The tarball is copied into each container with `docker compose cp`.
3. **Install.** Run `splunk install app <tarball>` inside the container as the Splunk user, then restart Splunk and wait for the health check. A non-zero exit fails the session and keeps the command's output. The admin password must not appear in host process arguments or saved logs.
4. **Verify.** The app is listed at the version in `default/app.conf`, the installed files match the tarball's hashes, and `bin/web_ping.py` is executable and owned by the Splunk user.

The heavy forwarder, indexer, search head and single instance all install the package this way. The test config app `website_ping_inputs` is not baked into anything either: the single instance installs it the same way, and in the distributed stack it is copied to the deployment server's `etc/deployment-apps` so that it reaches the forwarder only by deployment.

A build failure is a test failure. A fresh clone is expected to fail today, because `scripts/package.py` adds `static`, which is empty and therefore not in git. The harness does not work around this.

To confirm on the first run: the exact user for `docker compose exec`, and that a Splunk restart inside the official image does not stop the container.

## Test layers

Six layers, cheapest first. Only layers 1 to 3 need containers and only layers 1 to 3 run per Splunk version, because layers 0, 4 and 5 do not depend on it.

| Layer | Runs on | Versions | Pytest marker | What it proves |
| --- | --- | --- | --- | --- |
| 0. Unit | Host venv, no Splunk | Python 3.9 interpreter plus the current one | `unit` | Config validation, event format, logger, HTTP check against the local `http.server` fixture (already in place) |
| 1. Single instance | One Splunk container | 9.4.x and 10.6.x | `single` | Scheme registers, `btool` defaults inherit, an event arrives with the expected fields, no ERROR lines in `splunkd.log` for the input |
| 2. Distributed | Heavy forwarder, indexer, search head, deployment server | 9.4.x and 10.6.x | `distributed` | The app works split across roles, config arrives through the deployment server, events flow forwarder to indexer to search head |
| 3. Network | Single instance plus the network overlay | 9.4.x and 10.6.x | `network` | Proxy, TLS, timeout, redirect, DNS and refused-connection behaviour end to end |
| 4. AppInspect | Host | Not version specific | `release` | Package passes AppInspect (Enterprise tags) |
| 5. Real host | Lab host, later the work host | Whatever runs there | manual | Real network, real proxy, real certificates |

Layer 3 reuses the single-instance stack on purpose: the proxy behaviour lives in the script's own HTTP code and Splunk's Python, so a full distributed stack per network scenario would only cost RAM.

When each layer runs:

- Every commit: layer 0.
- Before merging changes to `bin/`, `default/` or `README/`: layers 1 and 3 on both lines.
- Before a release: all layers, both lines, one after the other.

## Distributed topology

Five containers reproduce the roles that matter for this app, built from the roles the official image supports (heavy forwarder, indexer, search head, deployment server). The [docker-splunk deployment server example](https://splunk.github.io/docker-splunk/advanced/DEPLOYMENT_SERVER.html) is the starting point for the compose file.

&#91;embedded content: distributed test topology · 5 containers, 5 connections\]

The code app `website-ping` is installed on the heavy forwarder, indexer and search head. The config app `website_ping_inputs` with the monitored URLs reaches only the heavy forwarder, through the deployment server. Only the heavy forwarder therefore produces events.

| Check | Where | What it proves |
| --- | --- | --- |
| Config arrives | Heavy forwarder | `btool inputs list web_ping --debug` shows the stanza from `website_ping_inputs` and the merged `[web_ping]` defaults |
| Event reaches the indexer | Indexer | A `sourcetype=website-ping` event with the expected fields appears within two intervals |
| Visible on the search head | Search head | The same search returns the event, and `KV_MODE = auto` extracts the fields at search time |
| Roles stay clean | Search head, indexer | No `website-ping` events originate from them; the scheme is registered but no input runs |
| Disabled input | Heavy forwarder | `disabled = 1` in the deployed config stops new events without ERROR lines |
| Forwarder outage | Heavy forwarder | Stopping the container produces no events and no errors elsewhere; restarting resumes events |

**Both version lines.** `pytest -m distributed --splunk-line all` starts this stack once for 9.4.x and once for 10.6.x, one after the other, from the same compose file. Only the image tag and the license flags differ: 10.x images need `SPLUNK_GENERAL_TERMS`, and the fixture sets the flags per line. Every check in the table runs unchanged on both lines, so a difference between 9.4 and 10.6 shows up as one failing check on one line.

## Proxy and network scenarios

Every scenario asserts on the event that reaches the index, and where it matters also on the target's and the proxy's access logs, so "the check did not use the proxy" is a measured fact and not an assumption.

The overlay adds helper containers next to the single-instance stack: a target server (plain, TLS and a deliberately broken one), Squid as proxy, mitmproxy as a TLS-intercepting proxy, Toxiproxy for latency and cut connections, and dnsmasq as resolver. Image names are to confirm when the compose files are written. Certificates are generated with `openssl` at session start into a git-ignored folder, never committed.

| Scenario | How it is built | Expected event | Phase |
| --- | --- | --- | --- |
| Normal 200 | Target answers 200 | `response_code=200`, `timed_out=0`, no `error` | 1 |
| 404 and 503 | Target returns the status | `response_code` equals the status, no `error` | 1 |
| Redirect chain up to the limit | Distinct URLs, N equal to `max_redirects`, at limits of 3, 10 (the default) and 50 (the highest accepted value) | Final `response_code=200`, no `error` | 1 |
| Repeated URL within the limit | One URL redirects to itself 8 times, then answers 200, with `max_redirects=10` | Final `response_code=200`, no `error` | 1 |
| Every redirect status | One redirect each with 301, 302, 303, 307 and 308 | Final `response_code=200`, no `error` | 1 |
| Redirect limit hit | Distinct URLs, N one above `max_redirects`, at limits of 3, 10 and 50 | 3xx `response_code` plus `error`, and the target log shows exactly `max_redirects` + 1 requests | 1 |
| Redirect loop | One URL always redirects to itself, default `max_redirects` | 3xx `response_code` plus `error`, and the target log shows exactly 11 requests | 1 |
| Redirects disabled | `max_redirects=0`, target redirects once | 3xx `response_code` plus `error`, and the target log shows exactly 1 request | 1 |
| Connection refused | Closed port on the target host | `response_code=0` plus `error` | 1 |
| Hang | Port accepts, never answers | `timed_out=1` after `timeout` seconds | 1 |
| Slow body | Toxiproxy delays the body past the total deadline | `timed_out=1`, status code kept | 1 |
| Trickled body | Target sends headers, then a few bytes per second past `timeout` | `timed_out=1`, status code kept, `total_time` at most `timeout` plus 2 seconds | 1 |
| DNS failure | Name under `.invalid`, or dnsmasq answering NXDOMAIN | `response_code=0` plus `error` | 1 |
| Bad certificates | Expired, self-signed and wrong-hostname certificates | `response_code=0` plus `error` (verification stays on) | 1 |
| Environment proxy ignored | `HTTP_PROXY` and `HTTPS_PROXY` set in the container, pointing at a logging Squid; target also reachable directly | Normal event, and zero requests in the Squid log | 1 |
| No direct route | Container only on the `internal: true` network, target reachable only through Squid, no proxy configured | `response_code=0` plus `error` | 1 |
| Explicit proxy | Same internal network, proxy configured for the input | `response_code=200`, request visible in the Squid log | 3 |
| Proxy with authentication | Squid requires basic auth; right and wrong credentials | Right: 200. Wrong: 407 recorded. Exact result settled when Phase 3 is designed | 3 |
| TLS-intercepting proxy | mitmproxy re-signs with its own CA | Verification fails unless the CA is configured | 3 |

Some of these rows are expected to fail against the current code, and that is their purpose. Python's built-in redirect limits (10 in total, 4 repeats of one URL) stop the request before the app's own limit does, so the repeated-URL, loop and above-10 chain rows should find a defect, and Python 3.9 does not follow 308. `timeout` limits the whole check: if the full body has not loaded when it expires, the check ends and reports `timed_out=1`. The trickled-body row should find that the deadline is only checked after a full read returns. These defects are left unfixed for now, and the tests stay as written and stay red until the app is corrected.

The Phase 1 rows are the ones that gate the first release. The Phase 3 rows are written as skipped tests with the expected behaviour in the docstring, so they exist before the feature does.

## Repo layout and how to run

The app stays at the repo root. Tests and tooling stay out of the package because `scripts/package.py` only adds the folders it lists.

```
website-ping/
  bin/ default/ metadata/ README/ static/   the app, packaged by scripts/package.py
  tests/
    test_*.py                   layer 0 (existing files stay here)
    conftest.py                 --splunk-line option; a bare pytest never starts containers
    integration/
      versions.toml             pinned image tag per version line
      conftest.py               compose fixtures, preflight, build and install
      compose/
        single.yml              one Splunk container
        distributed.yml         HF, indexer, search head, deployment server
        network.yml             overlay: target, Squid, mitmproxy, Toxiproxy, dnsmasq
      fixtures/                 proxy configs, cert script (certs/ is git-ignored)
      test_smoke.py             layer 1
      test_distributed.py       layer 2
      test_network.py           layer 3
  scripts/
    package.py                  builds the tarball for install and AppInspect
    test-clean.sh               remove leftovers by label
  pyproject.toml
```

Commands, run from a venv on the host:

```
pytest --cov --cov-report=term-missing
pytest tests/integration -m single       --splunk-line 9.4
pytest tests/integration -m single       --splunk-line 10.6
pytest tests/integration -m distributed  --splunk-line all
pytest tests/integration -m network      --splunk-line all
scripts/test-clean.sh
```

`--splunk-line all` runs the lines one after another. A failed run leaves its containers up when `--keep` is passed, so the failure can be inspected with `docker exec`; the next normal run or `test-clean.sh` removes them.

What each integration session does, in order: run the isolation preflight, build the package, start the stack from the pinned image for the chosen line, wait for the container health check instead of sleeping, install the package and the test config app as described in "Building and installing the app", and only then run the tests. Splunk's first start takes minutes, which is the main reason layers 1 to 3 are not part of the per-commit run.

## Risks, limits and open questions

The biggest practical limits are RAM and startup time, not test logic.

**Risks and limits**

- **Memory.** The distributed stack at the starting limits (3 GB plus three times 2 GB) reserves up to 9 GB next to the main Splunk. If the machine is tight, drop the search head to a shared role with the deployment server.
- **Startup time.** Every integration run starts fresh containers. Measure the first full run and record the real durations here.
- **Host architecture.** The host is x86-64 (confirmed), so the official amd64 images run natively. The [10.6 release notes](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6/whats-new/whats-new-in-10.6) list ARM64 support only as conditional availability in FIPS 140-3 mode, so the planned arm64 k8s cluster is not a target for this harness.
- **One machine is not a network.** Containers show that each failure class is handled. They do not show how a specific firewall or proxy product behaves; layer 5 stays necessary.
- **Image tags.** Tag spelling under the four-segment version format is unverified (see the version matrix).

**Open questions**

1. Settled: Docker Engine on Linux, installed as described in "Prerequisite: Docker Engine".
2. Does 9.4 get a support promise in the README, or is it only tested? The matrix runs it either way.
3. Later: run layers 0 and 4 in GitHub Actions, and layers 1 to 3 too if runner resources allow. Not planned yet.
4. Python version per image, from the first smoke run.

## README section: Testing

Ready to paste into `README.md`. Fill in the pinned versions after the first run.

````markdown
## Testing

website-ping is tested on Splunk Enterprise 9.4.x and 10.6.x, standalone and in a distributed setup, including behind proxies. Splunk Cloud is not tested.

### Test layers

| Layer | Marker | What it checks |
| --- | --- | --- |
| Unit | `unit` | Configuration validation, event format, logging and the HTTP check, without Splunk |
| Single instance | `single` | The app installs, the input registers, defaults are inherited and events arrive with the expected fields |
| Distributed | `distributed` | Heavy forwarder, indexer, search head and deployment server: config is deployed and events flow end to end |
| Network | `network` | Proxy, TLS, timeout, redirect, DNS and connection-failure behaviour |
| Release | `release` | AppInspect on the packaged app |

A failed check is data: every network scenario asserts on the event that reaches the index (`response_code`, `timed_out`, `error`), not on a crash.

### Requirements

- Python 3.9 or newer, in a virtual environment (`pip install -e ".[test]"`)
- Docker Engine with Compose v2 on an amd64 Linux host
- About 10 GB of free RAM for the distributed run; the stacks run one at a time

### Running the tests

```
pytest --cov --cov-report=term-missing
pytest tests/integration -m single      --splunk-line 9.4
pytest tests/integration -m single      --splunk-line 10.6
pytest tests/integration -m distributed --splunk-line all
pytest tests/integration -m network     --splunk-line all
```

The Splunk image tags are pinned in `tests/integration/versions.toml`. Splunk 10.x images require accepting the Splunk General Terms; the test fixtures pass the license flags for you, which means running them signifies that you accept the terms.

### Isolation

The integration tests never use fixed host ports, host networking or bind mounts of Splunk directories. Each run uses its own Compose project, private network and named volumes, publishes ports on `127.0.0.1` only, and checks these rules before starting. A Splunk instance already running on the same machine is not affected.

Leftovers from an interrupted run are removed with:

```
scripts/test-clean.sh
```
````

