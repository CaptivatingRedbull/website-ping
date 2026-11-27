# Changelog
 
All notable changes to Website Ping are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0.0, any minor version may
change behaviour.
 
## [Unreleased]

## [0.2.0] - 2026-11-27

### Added

- Side-by-side build (`scripts/package.py --flavor side-by-side`): the same app
  with its own input `website_ping`, defaults stanza `[website_ping]` and settings
  file `website_ping.conf`, and with no object shared with other apps, so it runs
  on an instance where Website Monitoring stays installed. Releases include both
  packages. See [docs/side-by-side.md](docs/side-by-side.md).
- The start line in `website_ping.log` names the build (`flavor=drop-in` or
  `flavor=side-by-side`).

### Fixed

- `DATETIME_CONFIG = NONE` now applies only to events of the app's own inputs
  (`[source::web_ping://...]`). It was set on the sourcetypes `web_ping` and
  `web_ping:response`, which also changed the event time of other data with those
  sourcetypes on the instance, for example Website Monitoring's. Inputs that set
  their own `sourcetype` now get it as well.

## [0.1.0] - 2026-11-23
 
First public release. Website Ping replaces Website Monitoring 2.9.7 by Luke
Murphey on Splunk Enterprise 9.4 and 10.x (on premises). To move from Website
Monitoring, follow [docs/migration.md](docs/migration.md).
 
### Added
 
- Modular input `web_ping` that accepts every `[web_ping://...]` setting of
  Website Monitoring 2.9.7 with the same meaning, and reads
  `website_monitoring.conf`.
- Events in Website Monitoring's format: same sourcetype `web_ping`, same fields,
  plus the response body event (`return_body`) and response headers
  (`return_headers`).
- Content checks (`should_contain_string`) and content hashes (`content_md5`,
  `content_sha224`).
- Basic and Digest authentication with passwords from Splunk's storage/passwords,
  and client certificates.
- HTTP proxies from `website_monitoring.conf` and from splunkd's environment
  (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, including CIDR entries).
- Certificate checks on request: `ssl_verify` and `ca_certs`.
- New field `error` with the reason when a check fails.
- Website Monitoring's macros, eventtype, tag, `http_response_codes` lookup and
  saved searches, under the same names.
- Dashboards without custom JavaScript under the old view names: Status Overview,
  Status History, Site Changes, Executive Summary and the Health views.
- Own log file `website_ping.log` (sourcetype `website_ping:log` in `_internal`)
  with a heartbeat every minute, and the alert `Website Ping Runner Silent`.
- Support for Splunk's Python 3.9 (9.4, 10.0) and 3.13 (10.2 and later); standard
  library only, no bundled third-party packages.
- Migration guide `docs/migration.md`.
### Changed (compared with Website Monitoring 2.9.7)
 
- App ID `website_ping`; it must not run on the same instance as Website
  Monitoring.
- All inputs run in one process with their own scheduler; configuration is read
  at start, `website_monitoring.conf` again every 10 minutes.
- `timeout` covers the whole check (connect, redirects, headers and body).
- `_time` is always the end of the check.
- Default user agent is `Splunk Website Ping/<version>`.
- TLS 1.2 is the minimum on every Splunk version.
- `proxy_ignore` applies only to the inputs of its own stanza.
- The alert `Website Performance Problem` describes a timeout as `Connection
  timed out`, and the availability searches show failed connections as
  `Connection failed`.
See "What behaves differently" in [docs/migration.md](docs/migration.md) for the
full list.
 
### Removed
 
- Custom JavaScript, the setup page, the feature tour, the `webping` search
  command and the views `adhoc_web_ping`, `web_ping_batch_create`,
  `setup_website_monitoring` and `test_website_monitoring`.
- Plain-text passwords in `inputs.conf` and `website_monitoring.conf`; store them
  in storage/passwords instead.
- SOCKS proxies, NTLM and Negotiate authentication.
- The lookup generator `web_ping_inputs_lookup_gen` and its lookup.
[Unreleased]: https://github.com/CaptivatingRedbull/website-ping/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/CaptivatingRedbull/website-ping/releases/tag/v0.2.0
[0.1.0]: https://github.com/CaptivatingRedbull/website-ping/releases/tag/v0.1.0
 