# Expected failures against the current code

These scenarios fail on the current app code because of known app defects. The
tests are written to expected behaviour, so they stay failing until the app is
fixed. They are not skipped or marked as expected failures.

A change may merge when every failing scenario is listed here for its version
line and fails on the listed field. Any other failure is new and blocks the
merge. A listed scenario that passes is reported too, so this list can be
corrected. Removing a row is part of the app fix for that defect.

A failure is an app defect only when the install, registration and event stages
passed. A failure before those stages is a harness or environment problem.

| Scenario | 9.4 | 10.6 | Field that differs on the current code | Defect |
| --- | --- | --- | --- | --- |
| `chain-at-50` | Fails | Fails | `response_code` 3xx, and the request count | Python's own redirect limit of 10 stops the request before `max_redirects` |
| `repeat-8` | Fails | Fails | `response_code` 3xx, and the request count | Python's limit of 4 repeats of one URL stops the request before `max_redirects` |
| `redirect-308` | Fails | Passes | `response_code` 308, and the request count | Python 3.9 on 9.4 does not follow a 308 redirect |
| `over-50` | Fails | Fails | `error` absent, and the request count | Python's redirect limit applies first, so the app never reports its own limit |
| `loop` | Fails | Fails | `error` absent, and the request count | Python's repeat limit applies first, so the app never reports its own limit |
| `trickled-body` | Fails | Fails | `total_time` about 16 | `timeout` is not a deadline for a slow body: `_drain` checks it only after a read returns |
| `tls-expired` | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |
| `tls-self-signed` | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |
| `tls-wrong-host` | Fails | Fails | `response_code` 200, `error` absent | Certificates are not verified inside Splunk (`PYTHONHTTPSVERIFY=0`) |

Until the certificate defect is fixed, `tls-valid` passes without proving that
verification works. A release requires that this list contains no certificate
defect.

On a fresh clone the session also stops at the build stage and
`tests/test_package_contents.py` fails, because `scripts/package.py` needs the
untracked, empty `static` folder.
