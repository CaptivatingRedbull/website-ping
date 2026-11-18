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

## Timeouts and redirects

`timeout` (seconds, default 30) is the time one check may take in total:
connecting, every redirect, the response headers and the whole body. A check
that is not done by then gives an event with `timed_out=True` and an empty
`response_code`, even if a status line had already arrived. Website Monitoring
applied `timeout` to each network operation instead, so a slow server could keep
one of its checks busy far longer.

`max_redirects` is the number of redirects a check follows (301, 302, 303, 307
and 308). On the next redirect the check stops with `exceeded_redirects=True` and
an empty `response_code`; `max_redirects = 0` stops at the first one. Blank or
negative means 30. A redirect loop runs into the same limit. An `Authorization`
header is not sent on when a redirect leads to another host name.

Known limits of the timeout: resolving the host name (DNS) cannot be interrupted
and can take longer than `timeout`, as with Website Monitoring. A server that
sends its TLS handshake slowly, a few bytes at a time, can also hold a check
beyond `timeout`.

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