# Migrating from Website Monitoring 2.9.7

Website Ping reads Website Monitoring's configuration files unchanged: the same
`[web_ping://...]` stanzas, the same `website_monitoring.conf`, the same stored
passwords. A migration removes Website Monitoring, installs Website Ping and copies
the configuration over. Events keep the sourcetype `web_ping` and their fields, and
the macros, eventtype, tag, lookup, saved searches and views keep their names.

Some settings that Website Monitoring accepted are refused, and some behaviour
differs. Read "Changes to make before the migration" and "What behaves
differently" first.

Both apps provide the input `web_ping`, so they cannot be installed on the same
instance at the same time. Each instance is migrated in one restart; checks that
fall due while Splunk is stopped run when it starts again, because Website Ping
continues Website Monitoring's schedule (same checkpoint files under
`$SPLUNK_HOME/var/lib/splunk/modinputs/web_ping/`).

## Changes to make before the migration

Make these while Website Monitoring is still installed. Website Monitoring
accepts every one of them, so nothing breaks in the meantime.

### Plain-text passwords

Website Ping reads passwords from `storage/passwords` only. An input with a
`password` in `inputs.conf` or a user name and password in its `url`
(`https://user:pass@host/`) does not run, and a `website_monitoring.conf` stanza
with a `proxy_password` cannot be used: the inputs that use it do not run. Each
case logs an ERROR.

Store each password and then remove the plain value:

| Plain value | Realm | User name |
| --- | --- | --- |
| `password` of `[web_ping://<name>]` | `web_ping://<name>` | the input's `username` |
| `user:pass@` in the `url` of `[web_ping://<name>]` | `web_ping://<name>` | the user from the URL; also set it as `username` |
| `proxy_password` in `website_monitoring.conf` | `website_monitoring_app_proxy` | `IN_CONF_FILE` |

Website Monitoring already prefers a stored password over the plain one, so the
inputs keep working after each step.

Store the passwords in an app that stays installed and that no deployment server
overwrites, for example `search`. Both apps find a password in any app. A
password stored in Website Monitoring's own app is kept in its
`local/passwords.conf` and has to be copied with the other files (see "Files to
copy"). With bash, so that the password appears neither on the screen nor in the
process list or the shell history:

```sh
read -rs -p 'Password: ' PW && echo &&
curl -k -u admin https://localhost:8089/servicesNS/nobody/search/storage/passwords \
  --data-urlencode 'name=<user name>' \
  --data-urlencode 'realm=web_ping://<name>' \
  --data-urlencode password@<(printf '%s' "$PW"); unset PW
```

Use your management port and admin user. curl asks for the admin password.

### Proxies

* SOCKS proxies (`proxy_type = socks4` or `socks5`) are not supported. Inputs that
  use such a stanza do not run. Use an HTTP proxy.
* `proxy_port` must be a number from 1 to 65535 when `proxy_server` is set. A
  blank port means 80, as before, and logs a warning; any other value stops the
  inputs that use the stanza.
* `[wp_defaults]` is a reserved stanza name in `website_monitoring.conf`. Rename a
  stanza of your own with that name, and the `configuration` of its inputs.
* A `website_monitoring.conf` kept in another app than Website Monitoring is read
  only if that app shares it with all apps: `export = system` for
  `[website_monitoring]` (or `[]`) in that app's `metadata/local.meta`. Otherwise
  move its stanzas into `website_ping/local/website_monitoring.conf` during the
  migration.

### Inputs

* Host names that contain `ß`, `ς`, joiner characters or full-width letters are
  refused, because their ASCII form differs between IDNA versions. Write the host
  in its ASCII form (`xn--...`), the name Website Monitoring sent.
* Sites that speak only TLS 1.0 or 1.1 cannot be checked any more (see "TLS and
  certificates").
* Inputs on search head cluster members: Website Monitoring ran them on the
  captain only. Website Ping has no such check, so every member would run every
  input. Move the inputs to a heavy forwarder.

### Things to decide

* User-Agent: inputs without `user_agent` sent
  `Splunk Website Monitoring (+https://splunkbase.splunk.com/app/1493/)`, set in
  Website Monitoring's `default/inputs.conf`. Website Ping sends
  `Splunk Website Ping/<version>`. If a site or firewall expects the old value,
  set it in `[web_ping]` of `local/inputs.conf`.
* Sites with NTLM or Negotiate authentication are checked without credentials
  (see "Authentication").

## Where the configuration is

Most of the configuration is in `$SPLUNK_HOME/etc/apps/website_monitoring/local/`,
but an input created in Splunk Web is stored in the app that was selected at the
time, often `search`. Inputs in other apps stay where they are and keep working
with Website Ping.

```sh
$SPLUNK_HOME/bin/splunk btool inputs list web_ping --debug
$SPLUNK_HOME/bin/splunk btool website_monitoring list --debug
```

The first column is the file each setting comes from. Values from
`website_monitoring/default/` go away with the app.

## Files to copy

From `$SPLUNK_HOME/etc/apps/website_monitoring/` into
`$SPLUNK_HOME/etc/apps/website_ping/`:

| File | What to do |
| --- | --- |
| `local/inputs.conf` | Copy to `local/`, or into an app of your own. |
| `local/website_monitoring.conf` | Copy to `local/`. |
| `local/passwords.conf` | Copy to `local/`. Its entries can only be read on the same host (they are encrypted with its `splunk.secret`); on another host, store the passwords again. |
| `local/macros.conf`, `local/eventtypes.conf`, `local/tags.conf`, `local/savedsearches.conf` | Copy to `local/`. They override the shipped objects of the same names. |
| `local/data/ui/views/*.xml` | Copy your own dashboards. Dashboards that load JavaScript of Website Monitoring lose it. A changed copy of `status_overview`, `status_history`, `site_changes`, `exec_summary`, `web_ping_logs` or `web_ping_status` replaces Website Ping's view of that name: copy it only if it works without Website Monitoring's JavaScript. |
| `lookups/*.csv` you added | Copy to `lookups/`. Skip `http_response_codes.csv` (shipped) and `web_ping_inputs.csv` (generated by Website Monitoring, not used). |
| `metadata/local.meta` | Merge its stanzas into `metadata/local.meta`. If `splunk install app` already created that file, keep its stanzas. |

Do not copy:

| File | Why |
| --- | --- |
| `local/authorize.conf` | Refers to the capability `edit_modinput_web_ping`, which Website Ping does not have. |
| `local/app.conf` | Describes Website Monitoring. |
| `local/restmap.conf`, `local/web.conf` | Website Monitoring's REST handlers are not part of Website Ping. |
| `local/commands.conf`, `local/searchbnf.conf` | The `webping` search command is not part of Website Ping. |
| `local/ui-tour.conf`, `local/data/ui/nav/`, `local/data/ui/manager/` | Website Ping has its own navigation and no feature tour or input pages of its own. |
| Views `adhoc_web_ping`, `web_ping_batch_create`, `setup_website_monitoring`, `test_website_monitoring` | Not part of Website Ping. |

Private objects of users are in `$SPLUNK_HOME/etc/users/<user>/website_monitoring/`.
Move each such folder to `$SPLUNK_HOME/etc/users/<user>/website_ping/`.

## Steps

Keep a copy of the whole `website_monitoring` folder until the migration is
confirmed; it is also what a rollback needs.

### Standalone instance or heavy forwarder

```sh
$SPLUNK_HOME/bin/splunk stop
mkdir -p ~/website_monitoring-backup
mv $SPLUNK_HOME/etc/apps/website_monitoring ~/website_monitoring-backup/
tar -xzf website_ping-<version>.tar.gz -C $SPLUNK_HOME/etc/apps
```

Copy the files listed in "Files to copy" from the backup into
`$SPLUNK_HOME/etc/apps/website_ping/`, make sure the Splunk user owns them, then
start Splunk:

```sh
$SPLUNK_HOME/bin/splunk start
```

On a heavy forwarder where nobody searches, turn off both alerts in
`website_ping/local/savedsearches.conf`:

```ini
[Website Performance Problem]
enableSched = 0

[Website Ping Runner Silent]
enableSched = 0
```

### Search head

The same steps without inputs: copy the knowledge objects, views and
`metadata/local.meta`.

In a search head cluster, changes made in Splunk Web are kept on the members.
Before you change the deployer, copy `etc/apps/website_monitoring/local/` from a
member. On the deployer, replace `etc/shcluster/apps/website_monitoring` with
`etc/shcluster/apps/website_ping`, put the copied files into its `local/`, and
push the bundle. Check afterwards that no member still has
`etc/apps/website_monitoring`.

### Deployment server

Replace the app in `$SPLUNK_HOME/etc/deployment-apps/`: remove
`website_monitoring`, add `website_ping` with the copied files in its `local/`.
In `serverclass.conf`, replace the app stanza of every server class and restart
the clients, because the input reads its stanzas when it starts:

```ini
[serverClass:<class>:app:website_ping]
restartSplunkd = true
```

```sh
$SPLUNK_HOME/bin/splunk reload deploy-server
```

The clients remove `website_monitoring` with everything in it, including a
`local/passwords.conf` written on the client. Passwords stored on a client
belong in an app the deployment server does not manage.

### After the start

```
index=_internal sourcetype=website_ping:log (WARN OR ERROR)
sourcetype=web_ping earliest=-15m | stats count by source
```

The first search lists inputs that do not run or have a problem, with the reason.
The second shows that events arrive.

## What behaves differently

### Checks

* `timeout` is the time for the whole check: connecting, redirects, headers and
  body. Website Monitoring applied it to each network operation. A check with
  HTTP authentication can take up to twice `timeout`, because the request that
  asks for the scheme has its own `timeout`, as before.
* Every failure gives an event with an empty `response_code` and a new field
  `error` with the reason (a timeout has no `error`). Any unexpected error in a
  check still gives an event; Website Monitoring retried such a check every few
  seconds without writing one.
* `_time` is always the end of the check, for check events and body events.
  With Website Monitoring, a date in the page title or body could move `_time`.
* Requests are sent with `Connection: close`, so the response headers
  `Connection` and `Keep-Alive` (with `return_headers`) can differ.
* A compressed body that is cut off or corrupt is a failed check
  (`error=ContentDecodingError: ...`); Website Monitoring used the part it got.
  `x-gzip` and several codings in a row are decoded; Website Monitoring hashed
  such bodies undecoded.
* Content hashes can change once for a body whose `Content-Type` is not a text
  type and names no charset: it is decoded as UTF-8, while Website Monitoring
  guessed the charset from the bytes.
* `content_md5` is also written on FIPS hosts.
* A body event is not written for an empty body (Splunk dropped Website
  Monitoring's anyway). Control characters are removed from body events.
* Redirects to host names with non-ASCII letters work.

### TLS and certificates

* TLS 1.2 is the minimum on every Splunk version. A site that speaks only TLS 1.0
  or 1.1 gives an event with an `error` starting with `SSLError:`. On Splunk 9.4,
  Website Monitoring still accepted those sites.
* Certificates are still not checked by default. `ssl_verify = true` turns
  checks on, for all inputs in `[web_ping]` of `local/inputs.conf`; `ca_certs`
  names a CA file, which must contain the root certificate (an intermediate alone
  is not enough). A changed CA or client certificate file takes effect at the next
  restart.
* An unreadable or mismatched client certificate gives an event with an `error`
  starting with `client certificate:` and sends no request.

### Authentication

* A site that offers NTLM gets no credentials; its event shows the `401`, and a
  WARN is logged once per input. Website Monitoring wrote no event for such a
  site and tried again about every 5 seconds.
* A site that offers only Negotiate gets no credentials; Website Monitoring sent
  Basic.
* Digest challenges with `SHA-512`, `auth-int` alone or `MD5-sess` without qop are
  not answered: the event shows the `401` and a WARN says why. Digest works on
  FIPS hosts.
* Basic credentials that are not Latin-1 are sent as UTF-8.

### Proxies

* `proxy_ignore` applies only to the inputs of its own stanza and only to proxies
  from the environment (`HTTP_PROXY`, `HTTPS_PROXY`). Website Monitoring set it
  as `NO_PROXY` for the whole process, so the last input to run decided for all
  of them. As before, it does not bypass `proxy_server`.
* Proxy user names and passwords may contain `@`, `:` and `%`.
* `NO_PROXY` entries in CIDR form (`10.0.0.0/8`) are honoured.
* `proxy_type = HTTP` in upper case is an HTTP proxy.
* A proxy from the environment with another scheme than `http://` gives an event
  with an `error`.

### Logs and operation

* All inputs run in one process. It logs to
  `$SPLUNK_HOME/var/log/splunk/website_ping.log`, indexed into `_internal` with
  the sourcetype `website_ping:log`; `web_availability_modular_input.log` is no
  longer written. Searches on the old log need the new source.
* The process logs a heartbeat every minute, and the new alert `Website Ping
  Runner Silent` reports hosts where it stopped.
* Changes to `website_monitoring.conf` take effect within 10 minutes,
  `thread_limit` at the next restart. Inputs changed in Splunk Web or over REST
  restart the input process at once; `inputs.conf` edited on disk or delivered by
  a deployment server takes effect at the next restart.

### Searches, alerts and dashboards

* The alert `Website Performance Problem` describes a timeout as `Connection
  timed out`; Website Monitoring described it as `Connection failed`.
* `inoperable_sites_rangemap` counts refused, unresolvable and redirect-limit
  failures as down; Website Monitoring counted them as up.
* The `format_events` macros and the saved searches `website_availability_overview`
  and `website_performance_problems` show a failed connection as `Connection
  failed` instead of an empty response code, and `website_performance_problems`
  now lists such sites.
* The macro `filter_disabled` passes every result through; the lookup generator
  `web_ping_inputs_lookup_gen` and its lookup are gone.
* Copied saved searches with `request.ui_dispatch_app = website_monitoring` still
  run; set it to `website_ping` so the links in their results work.
* Status Overview has one row per input, and its filter shows all inputs,
  failures or warnings; the choice "only enabled inputs" is gone.
* The views `adhoc_web_ping`, `web_ping_batch_create`, `setup_website_monitoring`
  and `test_website_monitoring`, the `webping` search command, the setup page and
  the feature tour are not part of Website Ping. Inputs are created in Settings >
  Data inputs or in `inputs.conf`.
* The Health views read `website_ping.log` and need a role that can search
  `_internal`.

## Rollback

Website Monitoring 2.9.7 refuses a stanza with a setting it does not know. Before
going back, remove `ssl_verify`, `ca_certs`, `log_level` and `python.required`
from every `[web_ping://...]` stanza and from `[web_ping]` in your `local/` files
and in other apps (a value in `[web_ping]` applies to every input).

```sh
$SPLUNK_HOME/bin/splunk stop
mv $SPLUNK_HOME/etc/apps/website_ping ~/website_ping-removed
mv ~/website_monitoring-backup/website_monitoring $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk start
```

Copy back any configuration changed since the migration from
`~/website_ping-removed/local/`. Stored passwords keep working: Website
Monitoring reads them too. The checkpoints are shared, so the schedule
continues.
