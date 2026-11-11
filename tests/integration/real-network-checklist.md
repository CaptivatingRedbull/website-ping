# Real-network checklist

Run by hand for each release, on each version line (9.4 and 10.6), on this
host. The harness's test network has no public sites or publicly issued
certificates, so these checks cover them. Never run them on the main Splunk.

They use a throwaway Splunk container on Docker's default bridge, which the
firewall rule covers. It has the single-instance limits, the
`website-ping.test=true` label, the password from an env file and no published
ports. `docker run --rm` removes it and its volumes when it stops. The
stanzas below exist only in this checklist, not in any harness config app, so
the harness's stanza URL check does not apply to them.

## 1. Prepare

From the repository root, with Docker access:

```sh
python scripts/package.py                     # prints dist/website-ping-<version>.tar.gz
LINE_IMAGE=splunk/splunk:10.6.1.1             # or splunk/splunk:9.4.17
ENV_FILE=$(mktemp) && chmod 600 "$ENV_FILE"
printf 'SPLUNK_PASSWORD=%s\nSPLUNK_START_ARGS=--accept-license\nSPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com\n' \
  "Wp$(openssl rand -hex 12)" > "$ENV_FILE"
```

Setting those two variables accepts Splunk's license and General Terms for
this container.

## 2. Start the throwaway container

```sh
docker run -d --rm --name wptest-realnet \
  --label website-ping.test=true \
  --memory 2g --memory-swap 2g --cpus 2 \
  --env-file "$ENV_FILE" \
  "$LINE_IMAGE"
until docker inspect -f '{{.State.Health.Status}}' wptest-realnet | grep -q healthy; do sleep 10; done
```

## 3. Install the app and the stanzas

```sh
docker cp dist/website-ping-*.tar.gz wptest-realnet:/tmp/website-ping.tar.gz
docker exec -u splunk -e SPLUNK_USERNAME=admin wptest-realnet \
  /opt/splunk/bin/splunk install app /tmp/website-ping.tar.gz
docker exec -i -u splunk wptest-realnet bash -c \
  'mkdir -p /opt/splunk/etc/apps/wptest_realnet/local && cat > /opt/splunk/etc/apps/wptest_realnet/local/inputs.conf' <<'EOF'
[web_ping://realnet-valid]
title = realnet-valid
url = https://example.com/
interval = 3600

[web_ping://realnet-expired]
title = realnet-expired
url = https://expired.badssl.com/
interval = 3600

[web_ping://realnet-self-signed]
title = realnet-self-signed
url = https://self-signed.badssl.com/
interval = 3600

[web_ping://realnet-wrong-host]
title = realnet-wrong-host
url = https://wrong.host.badssl.com/
interval = 3600

[web_ping://realnet-blocked]
title = realnet-blocked
url = http://10.212.0.1:8088/
interval = 3600
timeout = 5
EOF
docker exec -u splunk -e SPLUNK_USERNAME=admin wptest-realnet /opt/splunk/bin/splunk restart
```

## 4. Read the results

Wait about a minute after the restart, then:

```sh
docker exec -u splunk -e SPLUNK_USERNAME=admin wptest-realnet /opt/splunk/bin/splunk search \
  'index=main sourcetype=website-ping title=realnet-* | table title response_code timed_out error total_time' \
  -earliest_time -15m
```

| Stanza | Expected |
| --- | --- |
| `realnet-valid` | `response_code=200`, `timed_out=0`, no `error`. Verification passes. |
| `realnet-expired` | `response_code=0`, `error` matches `^SSLCertVerificationError: .*certificate has expired` |
| `realnet-self-signed` | `response_code=0`, `error` matches `^SSLCertVerificationError: .*self[- ]signed certificate` |
| `realnet-wrong-host` | `response_code=0`, `error` matches `^SSLCertVerificationError: .*Hostname mismatch` |
| `realnet-blocked` | `response_code=0`, `timed_out=1`. The firewall rule drops it silently and nothing listens on that port. |

The three certificate rows cannot pass until the app verifies certificates
inside Splunk (see `expected_failures.md`). A release requires them to pass.

## 5. Remove the container

```sh
docker stop wptest-realnet      # --rm removes it and its volumes
rm -f "$ENV_FILE"
scripts/test-clean.sh
```

## Sign-off

One line per release and version line, by the developer. Record any row that
did not match.

| Release | Line | Date | Result | Signed off by |
| --- | --- | --- | --- | --- |
| | | | | |
