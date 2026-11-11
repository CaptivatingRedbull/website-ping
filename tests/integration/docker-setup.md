# Docker setup for the integration tests

This runbook installs Docker Engine on the developer's host so the integration
tests can run without disturbing the main Splunk. It is specific to this host:
Ubuntu 26.04 (`resolute`), Docker's data under `/data/docker`, the LAN on
`192.168.8.0/21`, and the main Splunk running as the systemd unit `Splunkd`.

The install ran on 2026-11-10 between 11:50 and 11:52 UTC. The before and after
records are in `~/docker-install-records/before` and `~/docker-install-records/after`.

The commands in steps 1 to 7 were confirmed by the developer on 2026-11-11 as
the ones that were run. The "Recorded result" lines are taken from the records
and the current system. The uninstall steps in section 9 have never been run.

## 1. Before-install records

Run before anything is installed, so the uninstall can be checked against them.

```sh
mkdir -p ~/docker-install-records/before && cd ~/docker-install-records/before
ip addr > ip-addr.txt
ip route > ip-route.txt
sysctl net.ipv4.ip_forward > ip-forward.txt
sudo iptables-save > iptables.txt
sudo nft list ruleset > nft.txt
sudo ufw status verbose > ufw.txt
systemctl show Splunkd -p ActiveEnterTimestamp -p MainPID > splunkd.txt
```

Recorded result (11:50:07 UTC):

* `net.ipv4.ip_forward = 0`
* Routes: only `eno4`, `192.168.8.0/21`, default via `192.168.10.1`.
* `ufw`: active, default deny incoming, allow outgoing, routed disabled. One rule:
  `22/tcp (OpenSSH) ALLOW IN Anywhere`.
* Main Splunk: `MainPID=566416`, `ActiveEnterTimestamp=Sun 2026-11-08 13:46:06 UTC`.

## 2. Docker daemon configuration

Written before Docker is installed, so the first start already uses these
addresses and this data root. The bridge `10.212.0.1/24` and the pool
`10.213.0.0/16` together sit inside `10.212.0.0/15`, which the firewall rule in
step 4 covers.

```sh
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<'EOF'
{
  "data-root": "/data/docker",
  "bip": "10.212.0.1/24",
  "default-address-pools": [{ "base": "10.213.0.0/16", "size": 24 }]
}
EOF
```

Recorded result: `/etc/docker/daemon.json`, owner root, mode 644, written at
11:50, with exactly the content above.

## 3. systemd drop-in: start Docker only when `/data` is mounted

```sh
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/10-require-data.conf <<'EOF'
[Unit]
RequiresMountsFor=/data
EOF
sudo systemctl daemon-reload
```

Recorded result: the file exists with that content, written at 11:50, and
`systemctl show docker -p DropInPaths -p RequiresMountsFor` reports
`DropInPaths=/etc/systemd/system/docker.service.d/10-require-data.conf` and
`RequiresMountsFor=/data`.

## 4. Firewall rule

Blocks the test subnets from the main Splunk's ports. It is inserted first, so
no later rule can allow the traffic. The rule also covers ports where nothing
listens today.

```sh
sudo ufw insert 1 deny proto tcp from 10.212.0.0/15 to any port 8000,8088,8089,9997
```

Recorded result (`after/iptables.txt`), the first rule in `ufw-user-input`,
before the OpenSSH rule:

```text
-A ufw-user-input -s 10.212.0.0/15 -p tcp -m multiport --dports 8000,8088,8089,9997 -j DROP
```

The records hold no `ufw status` taken after the install.

## 5. Install Docker Engine from Docker's repository

```sh
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu resolute stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Recorded result:

* `/etc/apt/keyrings/docker.asc`, mode 644, written at 11:51.
* `/etc/apt/sources.list.d/docker.list` contains the `deb` line above.
* Installed packages: `docker-ce` and `docker-ce-cli` `5:29.9.3-1~ubuntu.26.04~resolute`,
  `containerd.io 2.4.2-3`, `docker-buildx-plugin 0.38.1-1`,
  `docker-compose-plugin 5.7.0-1`, `docker-ce-rootless-extras 5:29.9.3-1`.
* Docker started at 11:51:56 UTC with data root `/data/docker`.

## 6. Add the developer to the `docker` group

Membership in this group is equivalent to root on this host. The harness never
runs privileged containers and never mounts the Docker socket.

```sh
sudo usermod -aG docker "$USER"
```

Recorded result: `getent group docker` shows `docker:x:983:snape`. A shell
started before this step has no access to Docker. Run commands as
`sg docker -c '<command>'`, or log in again.

## 7. After-install checks

```sh
mkdir -p ~/docker-install-records/after && cd ~/docker-install-records/after
ip addr > ip-addr.txt
ip route > ip-route.txt
sysctl net.ipv4.ip_forward > ip-forward.txt
sudo iptables-save > iptables.txt
sudo nft list ruleset > nft.txt
systemctl show Splunkd -p ActiveEnterTimestamp -p MainPID > splunkd.txt
docker info --format '{{.DockerRootDir}}'
```

Compare with the before records. Recorded result (11:52:24 UTC):

* Main Splunk unchanged: `MainPID=566416`, `ActiveEnterTimestamp=Sun 2026-11-08 13:46:06 UTC`.
* `net.ipv4.ip_forward = 1`. Docker turned IP forwarding on.
* New interface `docker0` with `10.212.0.1/24`, and a route
  `10.212.0.0/24 dev docker0`. No other routes changed.
* New `DOCKER`, `DOCKER-BRIDGE`, `DOCKER-CT`, `DOCKER-FORWARD`,
  `DOCKER-INTERNAL` and `DOCKER-USER` chains, `FORWARD` jumps to `DOCKER-USER`
  and `DOCKER-FORWARD`, and a `nat` table with
  `MASQUERADE` for `10.212.0.0/24`.
* The firewall rule from step 4 is first in `ufw-user-input`.
* Docker's data root is `/data/docker`.

## 8. VPN ranges

If a VPN or another network is added later, check that its range does not
overlap `10.212.0.0/15`. If it does, change `bip` and `default-address-pools`
in `/etc/docker/daemon.json` and the source range of the firewall rule to a
free `/15`, restart Docker, and update `tests/integration/wptest/preflight.py`
and this runbook.

## 9. Uninstall

These steps have never been run, so they are untested. Remove all test
objects first with `scripts/test-clean.sh`.

```sh
sudo systemctl stop docker.socket docker.service containerd.service
sudo apt-get purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
  docker-compose-plugin docker-ce-rootless-extras
sudo rm /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
sudo rm /etc/docker/daemon.json
sudo rm /etc/systemd/system/docker.service.d/10-require-data.conf
sudo systemctl daemon-reload
sudo ufw delete deny proto tcp from 10.212.0.0/15 to any port 8000,8088,8089,9997
sudo gpasswd -d "$USER" docker
sudo sysctl -w net.ipv4.ip_forward=0
```

Docker's chains, the `nat` rules and the `docker0` interface stay until the
next reboot. After the reboot, compare `ip route`, `sysctl net.ipv4.ip_forward`,
`iptables-save` and `ufw status verbose` with the before records. Images and
volumes stay in `/data/docker` until that folder is removed by hand. Check that
nothing else uses it before removing it, because `/data` also holds the main
Splunk's indexes.
