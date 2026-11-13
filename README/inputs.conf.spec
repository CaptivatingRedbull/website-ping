[web_ping://<name>]
* Configures a check of one web site.
* Settings left blank use the default described below.

url = <string>
* The URL to check. Must use http or https and contain a host name.
* Must not contain a user name or password (user:password@host); such a stanza is
  rejected.
* Required.

interval = <string>
* How often to perform the check: a number with an optional unit, such as 30s,
  15m, 2h, 1d or 1w. Units: w, week, d, day, h, hour, m, min, minute, s (lower case).
* A number without a unit is seconds.
* Required.

title = <string>
* A short description of the site, typically its domain name.
* Default: the URL

configuration = <string>
* Which stanza of website_monitoring.conf to take the proxy and other settings from.
* Default: default

client_certificate = <string>
* Path to a client certificate, for sites that require client certificate
  authentication.
* Default: blank (no client certificate)

client_certificate_key = <string>
* Path to the key of the client certificate, if the key is in a separate file.
* Default: blank

username = <string>
* The user name for HTTP authentication.
* The password is read from storage/passwords, realm web_ping://<name>.
* Default: blank (no authentication)

password = <string>
* NOT SUPPORTED: a non-blank value is rejected and the stanza does not run.
* Store the password in storage/passwords with realm web_ping://<name> instead.

user_agent = <string>
* The User-Agent header sent to the site.
* Default: Splunk Website Ping/<app version>

should_contain_string = <string>
* Text that must appear in the response body. If it does not, the check reports
  has_expected_string=false.
* Default: blank (no content check)

timeout = <integer>
* The maximum number of seconds to wait for a response.
* A value of 0 or less is replaced by the default.
* Default: 30

max_redirects = <integer>
* The maximum number of redirects to follow.
* 0 turns off following redirects.
* -1 or blank follows redirects without a configured limit (at most 30).
* Default: blank

return_body = <boolean>
* If true (or 1), the response body is indexed as a separate event, up to the
  limit set in website_monitoring.conf.
* Default: false

return_headers = <boolean>
* If true (or 1), the response headers are added to the event.
* Default: false

warning_threshold = <integer>
* Response time in milliseconds above which the check counts as a warning.
* Blank or negative: not set.
* Default: blank

error_threshold = <integer>
* Response time in milliseconds above which the check counts as failed.
* Blank or negative: not set.
* Default: blank

ssl_verify = <boolean>
* If true (or 1), the server certificate is verified.
* Default: blank (use the setting in website_monitoring.conf)

ca_certs = <string>
* Path to a file of CA certificates used when ssl_verify is true.
* Default: blank (the system CA bundle)

log_level = <string>
* Log level for this input: DEBUG, INFO, WARN or ERROR.
* Default: INFO
