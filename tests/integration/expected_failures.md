# Expected failures against the current code

These scenarios fail on the current app code because of known app defects. The
tests are written to expected behaviour, so they stay failing until the app is
fixed. They are not skipped or marked as expected failures.

A change may merge when every failing scenario is listed here for its runtime
(Splunk line and interpreter) and fails on the listed field. Any other failure
is new and blocks the merge. A listed scenario that passes is reported too, so
this list can be corrected. Removing a row is part of the app fix for that
defect.

The column "Runtimes" lists the runtime ids on which the scenario fails, in the
form of the test ids (`<line>-py<interpreter>`, for example `10.2-py3.9`), or
`all` for every runtime of `--splunk-line all --python all`. The default run
covers the oldest and the newest line on the interpreter the app selects.
Scenario names are those of `test_network.py` unless the row says `parity:`
(`test_parity.py`, compared with the 2.9.7 fixtures).

| Scenario | Runtimes | Field that differs on the current code | Defect |
| --- | --- | --- | --- |
| | | | |
No scenario is expected to fail on the current code.
