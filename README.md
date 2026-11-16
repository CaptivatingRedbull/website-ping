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