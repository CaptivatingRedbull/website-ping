# Running Website Ping next to Website Monitoring

The normal (drop-in) build of Website Ping replaces Website Monitoring 2.9.7: it
uses the same input `web_ping`, the same `website_monitoring.conf` and the same
global names for its macros, saved searches and other objects. So the two apps
cannot be installed on the same instance.

The side-by-side build is the same app with these names changed. Install it on
an instance where Website Monitoring stays installed and runs unchanged, to try
Website Ping on real sites before you migrate. When the trial is over, switch to
the drop-in build (see "Switching to the drop-in build").

## Getting the package

Each release has both packages:

* `website_ping-<version>.tar.gz`: drop-in build
* `website_ping-<version>-side-by-side.tar.gz`: side-by-side build

To build it from a checkout:

```sh
python3 scripts/package.py --flavor side-by-side
# writes dist/website_ping-<version>-side-by-side.tar.gz
```

Both builds have the app ID `website_ping`, so only one of them can be installed
on an instance at a time. The side-by-side build shows as "Website Ping
(side-by-side)" in Splunk Web, and its start line in `website_ping.log` ends with
`flavor=side-by-side`.

## What is different

| | Drop-in build | Side-by-side build |
| --- | --- | --- |
| Input stanzas | `[web_ping://<name>]` | `[website_ping://<name>]` |
| Input defaults | `[web_ping]` | `[website_ping]` |
| Settings file | `website_monitoring.conf` | `website_ping.conf` (same stanzas and keys) |
| Input password realm | `web_ping://<name>` | `website_ping://<name>` |
| Event `source` | `web_ping://<name>` | `website_ping://<name>` |
| Checkpoints | `modinputs/web_ping/` | `modinputs/website_ping/` |
| Macros, eventtype, tag, lookup, saved searches, views | shared with all apps (`export = system`) | used only in the `website_ping` app (`export = none`) |

Unchanged:

* The sourcetypes `web_ping` and `web_ping:response`, and every event field. The
  shipped searches and dashboards are the same in both builds.
* The proxy password: realm `website_monitoring_app_proxy`, user name
  `IN_CONF_FILE`. Both apps use the same stored entry, so both use the same proxy
  account.
* The names of the macros and other objects. Because the side-by-side build does
  not share them, Website Monitoring keeps the global names, and searches in
  other apps keep using Website Monitoring's objects.
* The log file `website_ping.log` (Website Monitoring writes its own).

## Before you install

### A separate index

Both apps write events with the sourcetype `web_ping`. A search that selects
only by sourcetype counts both apps' events. Website Monitoring's
`website_monitoring_search_index` macro defaults to `()`, so its dashboards and
the `Website Performance Problem` alert search the role's default indexes.

Write Website Ping's events to an index of their own and keep that index out of
every role's default search indexes (`srchIndexesDefault`). Then set the index
macro inside the `website_ping` app, in
`$SPLUNK_HOME/etc/apps/website_ping/local/macros.conf`:

```ini
[website_monitoring_search_index]
definition = index=<your index>
```

If Website Monitoring's events go to an index that every role searches by
default, also set its own `website_monitoring_search_index` to that index, so its
dashboards and alert do not count Website Ping's events.

### Where the inputs go

Put the side-by-side inputs into an app of your own, not into
`website_monitoring`, and give each the index from above:

```ini
[website_ping://intranet]
url = https://intranet.example.com/health
interval = 5m
title = Intranet
index = <your index>
```

To compare both apps against the same sites, copy the stanzas of Website
Monitoring's inputs and change `web_ping://` to `website_ping://`. An input may
have the same name in both apps; the two stay separate.

Settings in `[web_ping]` of Website Monitoring (for example its `user_agent`) do
not apply to the side-by-side inputs. Put defaults for them in `[website_ping]`.

### website_ping.conf

Proxy, certificate and thread settings go into `website_ping.conf`, with the same
stanzas and keys as `website_monitoring.conf`. Copy Website Monitoring's file,
rename it, and put it into `website_ping/local/` or into your own app. A
`website_ping.conf` in your own app is read only if that app shares it with all
apps: in its `metadata/local.meta`:

```ini
[website_ping]
export = system
```

The reserved stanza `[wp_defaults]` and the rules of
[migration.md](migration.md) ("Proxies") apply as well.

### Passwords

Each input's password is read from realm `website_ping://<name>`. Store it a
second time, next to Website Monitoring's `web_ping://<name>` entry, for example
in the `search` app:

```sh
read -rs -p 'Password: ' PW && echo &&
curl -k -u admin https://localhost:8089/servicesNS/nobody/search/storage/passwords \
  --data-urlencode 'name=<user name>' \
  --data-urlencode 'realm=website_ping://<name>' \
  --data-urlencode password@<(printf '%s' "$PW"); unset PW
```

The changes of [migration.md](migration.md), "Changes to make before the
migration", apply to the side-by-side inputs too: no plain-text passwords, no
SOCKS proxies, ASCII host names for the characters listed there.

## Searches, alerts and dashboards

Inside the `website_ping` app, its dashboards and saved searches use its own
macros, eventtype and lookup, with the index from its `local/macros.conf`.

In every other app (for example `search`), the macros, eventtype, tag, lookup
and saved searches of Website Monitoring apply, as before. Users' own searches
keep showing Website Monitoring's data. To run one against Website Ping's data,
copy it into the `website_ping` app or name the index in it.

Customisations in `website_monitoring/local/`, for example the index macro, the
threshold macros or the alert exclusions in the eventtype
`filter_website_monitoring_alerts`, do not apply in the `website_ping` app. Copy
the ones you need into `website_ping/local/`.

Both apps schedule `Website Performance Problem`, each in its own app. Disable
one of them if you want only one set of alert notifications during the trial.

## Switching to the drop-in build

1. Remove Website Monitoring, as [migration.md](migration.md) describes.
2. In your input apps, rename `[website_ping://<name>]` to `[web_ping://<name>]`
   and `[website_ping]` to `[web_ping]`, and rename `website_ping.conf` to
   `website_monitoring.conf` (also in the `metadata/local.meta` stanza).
3. Make sure each input's password is stored under realm `web_ping://<name>`.
   Website Monitoring's entries may still be there.
4. Move `website_ping/local/` aside, remove the `website_ping` app folder, install
   the drop-in build and put `local/` back, renaming `website_ping.conf` in it
   too. Installing over the side-by-side build instead would leave
   `bin/website_ping.py` and `default/website_ping.conf` behind.
5. Restart Splunk. With a deployment server, use `restartSplunkd = true`.

After the switch:

* The sourcetype and fields stay the same. The `source` changes from
  `website_ping://<name>` to `web_ping://<name>`. Searches that group by `source`
  show two rows per site until the old one is out of their time range.
* The checkpoints start fresh, so each input runs its first check right after the
  start.
* If the index should change, change `index` in the inputs and the
  `website_monitoring_search_index` macro.
