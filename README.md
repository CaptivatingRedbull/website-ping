# Website Ping

(App ID: ```website_ping```)
A Splunk app for monitoring the uptime, responsetime, etc. of websites.

Inspired by [website-monitoring](https://github.com/LukeMurphey/splunk-website-monitoring/tree/master) 


## Python

The input runs on the Python interpreter that Splunk ships with:

| Splunk | Interpreter |
| --- | --- |
| 9.4 | Python 3.9 |
| 10.2 and later | Python 3.13 |

`default/inputs.conf` sets `python.required = 3.9,3.13`, and Splunk picks the
highest of these that it has. The code is written for Python 3.9 and tested on
3.9 and 3.13. Each check logs the interpreter and OpenSSL version on its start
line in `splunkd.log`, for example
`starting check url=... python=3.13.11 openssl="OpenSSL 3.5.9 29 Sep 2026"`.

To run the input on Python 3.9 on Splunk 10.x while that version still ships it,
set this in `local/inputs.conf` of this app:

```
[web_ping]
python.required = 3.9
```
