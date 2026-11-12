[wp_probe://<name>]
url = <string>
* A URL for the TLS check. Optional.

interval = <string>
* Read by the probe only. Left unparsed on purpose ("15m" must be accepted).

title = <string>

configuration = <string>
* Name of a website_monitoring.conf stanza. Logged only.

exit_after = <integer>
* Seconds after which the process exits 0. Off when unset.

sigterm_delay = <integer>
* Seconds the probe keeps running after SIGTERM (question 6, SIGKILL timeout).
