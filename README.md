# Website Ping

(App ID: ```website_ping```)
A Splunk app for monitoring the uptime, responsetime, etc. of websites.

Inspired by [website-monitoring](https://github.com/LukeMurphey/splunk-website-monitoring/tree/master) 


## Python

The input runs on the Python interpreter that Splunk ships with:

| Splunk | Interpreter |
| --- | --- |
| 9.4 | Python 3.9 |
| 10.2 and later | Python 3.13 |

`default/inputs.conf` sets `python.required = 3.9,3.13`, and Splunk picks the
highest of these that it has. The code is written for Python 3.9 and tested on
3.9 and 3.13. The input logs the interpreter and OpenSSL version on its start
line in `splunkd.log`, for example
`starting stanzas=12 invalid=0 thread_limit=200 pid=4711 python=3.13.11 openssl="OpenSSL 3.5.9 29 Sep 2026"`.

To run the input on Python 3.9 on Splunk 10.x while that version still ships it,
set this in `local/inputs.conf` of this app:

```
[web_ping]
python.required = 3.9
```

Splunk reads the interpreter setting from `[web_ping]` only; `python.required` in
an input stanza has no effect.

## How the inputs run

Splunk starts one process for all enabled `[web_ping://...]` stanzas. That
process runs each check when its `interval` has passed (`30s`, `15m`, `2h`, `1d`,
or seconds without a unit) and up to 200 checks at the same time. `interval` is
required; a stanza without one, or with any other invalid setting, logs an ERROR
and is not run, while the other stanzas run.

The time of each stanza's last run is kept in
`$SPLUNK_HOME/var/lib/splunk/modinputs/web_ping/`, in the same format as Website
Monitoring, so a restart or a migration from Website Monitoring keeps the
schedule instead of checking every site again at once.

Splunk starts the process again when inputs are added or changed (in Splunk Web
or over REST) and when Splunk restarts. A configuration delivered by a deployment
server takes effect after the next restart; give the server class
`restartSplunkd = true`. Splunk does not start the process again if it ends for
any other reason. It logs a `heartbeat` line every minute:

```
index=_internal sourcetype=website_ping:log heartbeat
```

The alert `Website Ping Runner Silent` reports a host whose process stopped
(see "Searches, macros and alerts").

## Timeouts and redirects

`timeout` (seconds, default 30) is the time one check may take in total:
connecting, every redirect, the response headers and the whole body. A check
that is not done by then gives an event with `timed_out=True` and an empty
`response_code`, even if a status line had already arrived. Website Monitoring
applied `timeout` to each network operation instead, so a slow server could keep
one of its checks busy far longer.
An input with HTTP authentication first asks
the site for its scheme, with its own `timeout` (see Authentication).

`max_redirects` is the number of redirects a check follows (301, 302, 303, 307
and 308). On the next redirect the check stops with `exceeded_redirects=True` and
an empty `response_code`; `max_redirects = 0` stops at the first one. Blank or
negative means 30. A redirect loop runs into the same limit. An `Authorization`
header is not sent on when a redirect leads to another host name.

Known limits of the timeout: resolving the host name (DNS) cannot be interrupted
and can take longer than `timeout`, as with Website Monitoring. A server that
sends its TLS handshake slowly, a few bytes at a time, can also hold a check
beyond `timeout`.

## Authentication

An input with `username` sends credentials when `storage/passwords` holds a
password with realm `web_ping://<name>`, in any app the input can read. A
`password` in `inputs.conf` and a user name or password in the URL are rejected:
the input does not run and logs an ERROR.

Like Website Monitoring, each check first sends one request without credentials
and reads the scheme from the `WWW-Authenticate` headers of the answer. That
request has its own `timeout` and is not part of `total_time`, so a check with
authentication can take up to twice `timeout`. If it fails, Basic is used.

* Basic: the credentials go with the timed request and with every redirect to
  the same host name. A wrong password gives `response_code=401`.
* Digest: the timed request goes out without credentials and the site's
  challenge is answered once, within the same `timeout`; a second `401` is the
  result. Algorithms `MD5`, `MD5-sess`, `SHA` and `SHA-256`, with `qop=auth` or
  without qop. The hashes are computed as not used for security, so Digest also
  works on FIPS hosts. Any other challenge (for example `SHA-512` or `auth-int`
  alone) is not answered: the event shows the `401` and one WARN per input says
  why.
* NTLM and Negotiate: not supported. Requests are sent without credentials, so
  the event shows the site's `401`, and one WARN per input says why. Website
  Monitoring wrote no event at all for a site that offered NTLM.
* Any other scheme: Basic credentials, as Website Monitoring sent, with one WARN
  per input.

Without a stored password, requests are sent without credentials and one WARN
per input says so. Passwords and `Authorization` values are never logged.

## Certificates and TLS

Certificates are not checked unless an input sets `ssl_verify = true`. Website
Monitoring did not check them either, and existing inputs keep working after a
migration. This deviates from Splunk's guidance, which is to verify
certificates.

For new deployments, turn verification on for every input in
`local/inputs.conf`; an input can still switch it off with
`ssl_verify = false`:

```ini
[web_ping]
ssl_verify = true
```
The same default can be set in `website_monitoring.conf`, for all inputs in
`[default]` or for the inputs of one proxy configuration in its stanza, together
with `ca_certs`. A value in `inputs.conf`, including one the input inherits from
`[web_ping]`, wins over `website_monitoring.conf`.
With verification on, a check tests the certificate chain and the host name.
`ca_certs` names a PEM file with the CAs to trust, for example an internal CA;
it must contain the root certificate, an intermediate alone is not enough.
Without `ca_certs` the input uses the file in `SSL_CERT_FILE`, if set, else the
first of these that exists: `/etc/ssl/certs/ca-certificates.crt` (Debian,
Ubuntu), `/etc/pki/tls/certs/ca-bundle.crt` (RHEL family, the Splunk container
images), `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`,
`/etc/ssl/ca-bundle.pem` (SUSE). Splunk's own Python has no usable CA store,
and the app ships none.

A certificate that fails gives an event with an empty `response_code` and an
`error` such as `SSLCertVerificationError: certificate has expired`,
`SSLCertVerificationError: self-signed certificate` or
`SSLCertVerificationError: Hostname mismatch, ...`. If the CA file cannot be
read or no bundle exists, the check sends no request; `error` is
`ca_certs not readable: <path>` or `no CA bundle found, set ca_certs`, and
`website_ping.log` gets one ERROR line. The CA file is read once when the
input starts; a changed file takes effect at the next restart.

Splunk starts its Python processes with `PYTHONHTTPSVERIFY=0`. The input does
not depend on it: every check uses its own TLS settings.

Every check requires TLS 1.2 or later, with or without verification and on
every Splunk version. A site that speaks only TLS 1.0 or 1.1 gives an empty
`response_code` and an `error` starting with `SSLError:`. On Splunk 9.4,
Website Monitoring still accepted those sites.

Python 3.9 and 3.13 check certificates the same way: the stricter checks that
Python 3.13 turns on by default are off, so a certificate accepted on Splunk
9.4 is accepted on 10.x and the other way round.

A site that requires a client certificate gets the one in `client_certificate`
(PEM, with the key in the same file or in `client_certificate_key`), with or
without verification, also through a proxy. Encrypted keys are not supported, as
in Website Monitoring. If the files cannot be read, the key does not match the
certificate or it is encrypted, the check sends no request; `error` starts with
`client certificate:` and names the file, for example
`client certificate: key does not match the certificate: <path>`, and
`website_ping.log` gets one ERROR line. Like the CA file, the certificate is
read once and a changed file takes effect at the next restart.

## Proxies

An input uses the HTTP proxy of the `website_monitoring.conf` stanza it names with
`configuration = <name>`, else the one in `[default]`:

```ini
[corporate]
proxy_server = proxy.example.com
proxy_port = 3128
proxy_user = monitor
```

That proxy carries every request of the check, redirects included; `proxy_ignore`
and `NO_PROXY` do not apply to it, as in Website Monitoring. The proxy password
comes from `storage/passwords`, realm `website_monitoring_app_proxy`, user
`IN_CONF_FILE`; a `proxy_password` in the file is refused. User and password may
contain any character, `@`, `:` and `%` included. For https the input opens a
CONNECT tunnel; certificate checks and the TLS 1.2 minimum apply to the site
behind it, and the timeout covers the tunnel too.

Without a proxy in its stanza, an input uses the proxy from splunkd's environment
(for example set in `$SPLUNK_HOME/etc/splunk-launch.conf`): `HTTP_PROXY` for http
URLs, `HTTPS_PROXY` for https URLs. Hosts listed in `NO_PROXY` or in the stanza's
`proxy_ignore` are reached directly; `proxy_ignore = *` turns environment proxies
off. Unlike Website Monitoring, `proxy_ignore` applies only to the inputs that use
its stanza, and the environment is never changed. Only `http://` proxy URLs are
supported; another scheme gives an event with an `error`.

SOCKS proxies (`proxy_type = socks4` or `socks5`) are not supported: inputs that use
such a stanza do not run, and `website_ping.log` has an ERROR that names the input
and the stanza.

Events carry the stanza's `proxy_server`, `proxy_type`, `proxy_port` and, if set,
`proxy_user`, whichever way the request went, as Website Monitoring reported them.
With `log_level = DEBUG`, every request logs its route without the password:
`direct`, `env http://proxy:3128` or `conf corporate http://proxy:3128 user=monitor`.

## Content checks

Every check that gets a response, error statuses included, adds `content_md5`,
`content_sha224` and `content_size` to its event. They describe the body as text,
after gzip or deflate compression is undone: the body is decoded with the
`charset` of its `Content-Type`, as ISO-8859-1 for a text type without one, and
as UTF-8 otherwise (also for a charset Python does not know); bytes that do not
decode become U+FFFD. The hashes are of that text encoded as UTF-8, and
`content_size` counts its characters. These are Website Monitoring's rules, with
one exception: for a body whose `Content-Type` names no charset and is not a text
type, Website Monitoring guessed the charset from the bytes. Such a body with
bytes that are neither ASCII nor UTF-8 gets other hashes after the migration.
`content_md5` is also written on FIPS hosts, where Website Monitoring left it out.

Only the first 50 MiB of a body are read; the hashes of a larger body cover those,
and `website_ping.log` has a WARN.

`should_contain_string` adds `has_expected_string=true` or `false`: whether the
decoded text contains the string, case-sensitive. `return_headers = true` adds a
`header_<Name>` field for every response header, in the order received; repeated
headers such as `Set-Cookie` are joined with `, `.

`return_body = true` indexes the decoded body as a second event with the
sourcetype `web_ping:response` (`<sourcetype>:response` for an input with its own
sourcetype), with the check event's source, host, index and time. It holds the
first `max_response_body_length` characters (`[default]` of
`website_monitoring.conf`, default 1000, -1 for the whole body, 0 for none). A
multi-line body stays one event, and its time is the time of the check even when
the page contains a date (the app ships `DATETIME_CONFIG = NONE` for the
sourcetype). Characters that XML does not allow, such as control characters in a
binary body, are removed; an empty body gives no body event. The body can contain
personal data from the page, so enable it only where that is acceptable.

## Logging

The input writes its log to `$SPLUNK_HOME/var/log/splunk/website_ping.log`,
rotated at 10 MB with five old files kept. Splunk indexes that directory into
`_internal`; the app gives the file the sourcetype `website_ping:log`:

```
index=_internal sourcetype=website_ping:log
```

Each line has a timestamp with UTC offset, the level, `stanza=<input>` for lines
about one input, and the app version:
`2026-11-16 11:34:00,123 +0100 INFO stanza=web_ping://example v=1.0.0 check done ...`.
`log_level` of an input (`DEBUG`, `INFO`, `WARN`, `ERROR`) sets the lowest level
written for it.

`splunkd.log` only gets the start and stop lines of the input. If the log file
cannot be opened, everything goes to `splunkd.log` instead, after an ERROR line
that says why.

## Searches, macros and alerts

The app ships the macros, eventtype, tag, lookup and saved searches of Website
Monitoring under the same names, so searches, dashboards and alerts written for
it keep working, and a `local/macros.conf`, `local/eventtypes.conf` or
`local/savedsearches.conf` copied from it overrides the same settings. The
lookup generator `web_ping_inputs_lookup_gen` is not shipped; the macro
`filter_disabled`, which used its lookup, passes every result through.

A check that got no response has an empty `response_code` (the field is set, not
missing). The searches and the `format_events` macros show such a check as
`Connection failed`, or `Connection timed out` when it timed out, and count it
as a failure.

Alerts, both scheduled on every Splunk instance that has the app:

* `Website Performance Problem` (every 5 minutes): sites with a failing response
  code, a timeout, no response, a slow response or content without the expected
  string. The macros `response_codes_to_alert_on` and `response_time_threshold`
  decide what counts as a failure. To exclude sites, set the search of the
  eventtype `filter_website_monitoring_alerts` in `local/eventtypes.conf`, for
  example `search = title=localhost`.
* `Website Ping Runner Silent` (every 10 minutes): hosts whose input process wrote
  a heartbeat in the last 24 hours but none in the last 10 minutes. Its checks
  have stopped; restarting Splunk on that host starts the process again.

Set the macro `website_monitoring_search_index` (default `()`, the role's default
indexes) to the index the inputs write to, for example `index=web`, if that
index is not searched by default.

All objects are shared with every app (`export = system`), a deliberate
exception to keeping an app's objects private: searches written for Website
Monitoring call its macros and lookup from other apps, often `search`. Users
with the `power` role may change the three threshold macros
(`response_codes_to_alert_on`, `response_time_threshold`,
`response_time_threshold_warning`).
