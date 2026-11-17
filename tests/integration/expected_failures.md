# Expected failures against the current code

These scenarios fail on the current app code because of known app defects. The
tests are written to expected behaviour, so they stay failing until the app is
fixed. They are not skipped or marked as expected failures.

A change may merge when every failing scenario is listed here for its runtime
(Splunk line and interpreter) and fails on the listed field. Any other failure
is new and blocks the merge. A listed scenario that passes is reported too, so
this list can be corrected. Removing a row is part of the app fix for that
defect.

The columns are the runtimes of `--python all`. The default run covers the
first two. Scenario names are those of `test_network.py` unless the row says
`parity:` (`test_parity.py`, compared with the 2.9.7 fixtures).

| Scenario | 9.4 / 3.9 | 10.6 / 3.13 | 10.6 / 3.9 | Field that differs on the current code | Defect |
| --- | --- | --- | --- | --- | --- |
| `tls-expired` | Fails | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |
| `tls-self-signed` | Fails | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |
| `tls-wrong-host` | Fails | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |
