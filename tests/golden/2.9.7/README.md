# Golden events: Website Monitoring 2.9.7

Captured by `tests/integration/test_golden.py` (commit 04). One JSON file per
scenario of `tests/integration/wptest/parity.py`: the normalised events
(`wptest/golden.py`), the target's request log lines and Squid's log lines for
the first `min_events` checks. `_capture.json` has the details of the capture.

* Website Monitoring 2.9.7, commit `442d08de5bbfed4a879de3b537eae0361de8e473`, built from the GitHub tag
  (`wptest/legacy.py`), installed in `website_monitoring` with the config in
  `local/`, as in production.
* Splunk image `splunk/splunk:9.4.17`, digest `sha256:8d3849f78c2814fd65e68a69aeaa4d1dc79f37e661dbe48e791f4552b025def5`.
* Captured 2026-11-12.
* Incomplete scenarios (fewer events than `min_events`): `ntlm-offered`.

Re-capture:

```sh
export WPTEST_ACCEPT_SPLUNK_TERMS=yes
pytest tests/integration -m golden --splunk-line 9.4 --golden-write
pytest tests/integration -m golden --splunk-line 9.4   # must pass: the capture is stable
```

Normalised: `total_time` and `request_time` to `<number>`, volatile response
headers to `<volatile>`, `_time` to `<time>` when splunkd assigned it on
arrival. Hashes, sizes and `host` are kept as captured.
