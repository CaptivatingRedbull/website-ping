[web_ping://<name>]
* Configures a check of one web site.
* Settings left blank use the default described below.

url = <string>
* The URL to check. Must use http or https and contain a host name.
* Must not contain a user name or password (user:password@host); such a stanza is
  rejected.
* A host name with non-ASCII letters is sent in its ASCII form (punycode). A host
  name containing ß, ς, joiner characters or full-width letters is rejected,
  because its ASCII form depends on the IDNA version; write such a host in its
  ASCII form (xn--...).
* Non-ASCII characters and spaces in the path and query are sent percent-encoded
  as UTF-8. The url field of the event keeps the text as written here.
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
* A stanza that does not exist: the input runs with that file's built-in defaults
  (no proxy) and logs a warning.
* Default: default

client_certificate = <string>
* Path to a client certificate in PEM format, for sites that require client
  certificate authentication. The file may also hold the private key.
* Used for HTTPS only, with ssl_verify on or off. The file is read once; a
  changed file takes effect at the next restart.
* If the file cannot be read, the key does not match or the key is encrypted,
  no request is sent and the event's error field starts with
  "client certificate:".
* Default: blank (no client certificate)

client_certificate_key = <string>
* Path to the private key of the client certificate (PEM, not encrypted), if it
  is not in the client_certificate file.
* Has no effect without client_certificate.
* Default: blank

username = <string>
* The user name for HTTP authentication.
* The password is read from storage/passwords, realm web_ping://<name>. Without
  a stored password, requests are sent without credentials.
* Each check first sends one request without credentials to learn the
  authentication scheme of the site. That request has its own timeout and is
  not part of total_time.
* Supported schemes: Basic, and Digest with the algorithms MD5, MD5-sess, SHA
  and SHA-256 and qop auth or none. A Digest challenge is answered once. NTLM
  and Negotiate are not supported; requests are then sent without credentials.
  Other schemes get Basic credentials.
* Default: blank (no authentication)

password = <string>
* NOT SUPPORTED: a non-blank value is rejected and the stanza does not run.
* Store the password in storage/passwords with realm web_ping://<name> instead.

user_agent = <string>
* The User-Agent header sent to the site.
* Default: Splunk Website Ping/<app version>

should_contain_string = <string>
* Text that must appear in the response body. If it does not, the event has
  the field has_expected_string set to false.
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
* If true (or 1), the response body is indexed as a separate event with the
  sourcetype <sourcetype>:response, up to the limit set in
  website_monitoring.conf (max_response_body_length, in characters). An empty
  body gives no such event.
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
* If true (or 1), the server certificate and the host name are checked. A
  certificate that fails gives an event with an empty response_code and the
  reason in the error field, for example
  "SSLCertVerificationError: certificate has expired".
* If false (or 0), any certificate is accepted, as in Website Monitoring.
* TLS 1.0 and 1.1 are refused either way.
* Default: blank, which means the ssl_verify of the input's stanza in
  website_monitoring.conf (see configuration), which is false unless set there.

ca_certs = <string>
* Path to a PEM file of the CA certificates to trust, used when ssl_verify is
  true. It must contain the root certificate; an intermediate alone is not
  enough.
* Blank: the ca_certs of the input's stanza in website_monitoring.conf. If that
  is blank too: the file named by the SSL_CERT_FILE environment variable, else the
* If the file cannot be read or no bundle exists, no request is sent and the
  error field says why.
* The file is read once, when the input starts.
* Default: blank

log_level = <string>
* Log level for this input: DEBUG, INFO, WARN or ERROR.
* Default: INFO
