# website_monitoring.conf: proxy, certificate and other settings for web_ping
# inputs, in the format Website Monitoring used.
#
# An input selects a stanza with configuration = <name> in inputs.conf; blank or
# "default" selects [default]. Settings in [default] apply to every stanza that
# does not set them itself.
#
# The input reads this file in the website_ping app's view: the file in
# website_ping/local/, or one in another app that exports it (export = system).
# Changes take effect within 10 minutes, except thread_limit, which is read when
# the input starts.
#
# Every setting below is valid in [default] and in a named stanza.

proxy_server = <string>
* The proxy server to use, as a host name or IP address.
* Examples: 1.2.3.4, proxy.example.com
* Default: blank (no proxy)

proxy_port = <integer>
* The port of the proxy server.
* Example: 8080
* Default: blank

proxy_user = <string>
* The user name for the proxy server.
* The password is read from storage/passwords, realm
  website_monitoring_app_proxy, user name IN_CONF_FILE.
* Default: blank (no proxy authentication)

proxy_password = <string>
* NOT SUPPORTED: a non-blank value is rejected. Inputs that use the stanza, or
  [default] if it is set there, do not run and log an ERROR.
* Store the password in storage/passwords instead, realm
  website_monitoring_app_proxy, user name IN_CONF_FILE.

proxy_type = <string>
* The protocol of the proxy server.
* Default: http

proxy_ignore = <string>
* A comma-separated list of hosts that are not reached through a proxy.
* The value * turns off proxies taken from the environment.
* Example: example.com,example.net
* Default: blank

thread_limit = <integer>
* The maximum number of checks that run at the same time.
* Read from [default] only, when the input starts.
* A value that is not an integer, or 0 or less, is replaced by the default.
* Default: 200

max_response_body_length = <integer>
* The maximum length of the response body indexed for inputs that set
  return_body to true.
* 0 indexes no body, even if an input sets return_body. -1 indexes the whole body.
* Read from [default] only.
* Default: 1000

ssl_verify = <boolean>
* The ssl_verify of every input that uses the stanza and leaves its own
  ssl_verify blank. See inputs.conf.spec.
* A value other than true, false, 1 or 0 makes the stanza unusable: inputs that
  use it do not run and log an ERROR.
* Default: false

ca_certs = <string>
* The ca_certs of every input that uses the stanza and leaves its own ca_certs
  blank. See inputs.conf.spec.
* Default: blank

[default]
* Settings for inputs without a configuration, and for every named stanza that
  does not set them itself.

[<name>]
* A configuration that inputs select with configuration = <name>.
* An input that names a stanza that does not exist runs with the defaults above
  (no proxy) and logs a warning.

[wp_defaults]
* Reserved. Shipped empty in default/website_monitoring.conf; the input reads
  [default] through it. Do not set anything in it and do not remove it.