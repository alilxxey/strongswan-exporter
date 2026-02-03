# strongswan-exporter

Prometheus exporter for strongSwan via VICI. Exposes current sessions (like `ipsec statusall`) and per-user traffic, plus connection history from `ike-updown` events.

## Features

- Active users and connection timestamps (EAP-ID by default)
- Per-CHILD_SA traffic counters (bytes/packets)
- Connection history: last connect/disconnect timestamps and counters (from VICI events)

## Requirements

- strongSwan with VICI enabled (default in modern releases)
- Access to the `charon.vici` socket (usually `/var/run/charon.vici`)

## Enable VICI (strongSwan)

VICI is a plugin. Ensure it is loaded and the socket path is known.

1) Find the VICI plugin config (common paths):

- `/etc/strongswan.d/charon/vici.conf`
- `/etc/strongswan/strongswan.d/charon/vici.conf`

2) Make sure it is enabled:

```
vici {
    load = yes
}
```

3) Restart strongSwan/charon and confirm the socket exists (default `/var/run/charon.vici`).

## Build

```bash
go build -o strongswan-exporter ./cmd/strongswan-exporter
```

## Run

```bash
./strongswan-exporter \
  -vici-socket /var/run/charon.vici \
  -listen :9814 \
  -metrics-path /metrics
```

## Debian package (.deb)

CI builds Debian packages (GoReleaser + nFPM) that install:

- binary: `/usr/bin/strongswan-exporter`
- systemd unit: `/lib/systemd/system/strongswan-exporter.service`
- defaults file: `/etc/default/strongswan-exporter`
- architectures: `amd64`, `arm64`

On tag `v*` packages are published in GitHub Releases.
For `main`/PR, packages are available as workflow artifacts.

Install latest release package:

```bash
ARCH="$(dpkg --print-architecture)"
VERSION="$(curl -fsSL https://api.github.com/repos/alilxxey/strongswan-exporter/releases/latest | sed -nE 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
[ -n "${VERSION}" ] || { echo "failed to detect latest release tag"; exit 1; }
curl -fLO "https://github.com/alilxxey/strongswan-exporter/releases/download/${VERSION}/strongswan-exporter_${VERSION#v}_linux_${ARCH}.deb"
sudo apt install "./strongswan-exporter_${VERSION#v}_linux_${ARCH}.deb"
```

The service is enabled and started during package install. Useful commands:

```bash
sudo systemctl status strongswan-exporter
sudo journalctl -u strongswan-exporter -f
```

To change runtime flags, edit `/etc/default/strongswan-exporter` and restart:

```bash
sudo systemctl restart strongswan-exporter
```

## Docker

Image is built in GitHub Actions and published to GHCR:

- on `main` push: `ghcr.io/alilxxey/strongswan-exporter:main`
- on tag `v*`: `ghcr.io/alilxxey/strongswan-exporter:vX.Y.Z`
- also publishes SHA-based tags

Pull the image:

```bash
docker pull ghcr.io/alilxxey/strongswan-exporter:main
```

Local build (optional):

```bash
docker build -t strongswan-exporter .
```

Run (mount the VICI socket into the container):

```bash
docker run --rm \
  -p 9814:9814 \
  -v /var/run/charon.vici:/var/run/charon.vici \
  ghcr.io/alilxxey/strongswan-exporter:main \
  -vici-socket /var/run/charon.vici
```

If the socket is restricted to root, run the container as root or adjust socket permissions.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: strongswan
    static_configs:
      - targets: ['localhost:9814']
```

## Metrics (key ones)

- `strongswan_user_connected{user,conn,remote_addr}`
- `strongswan_user_connected_at_seconds{user,conn,remote_addr}`
- `strongswan_user_last_connect_at_seconds{user,conn}`
- `strongswan_user_last_disconnect_at_seconds{user,conn}`
- `strongswan_user_connects_total{user,conn}`
- `strongswan_user_disconnects_total{user,conn}`
- `strongswan_child_bytes_in_total{user,conn,child,child_id,remote_addr}`
- `strongswan_child_bytes_out_total{user,conn,child,child_id,remote_addr}`
- `strongswan_child_packets_in_total{user,conn,child,child_id,remote_addr}`
- `strongswan_child_packets_out_total{user,conn,child,child_id,remote_addr}`
- `strongswan_child_installed_at_seconds{user,conn,child,child_id,remote_addr}`

## Example PromQL

- Who is connected now:
  ```promql
  strongswan_user_connected == 1
  ```

- When a user connected (active sessions):
  ```promql
  strongswan_user_connected_at_seconds
  ```

- Last disconnect time (history):
  ```promql
  strongswan_user_last_disconnect_at_seconds
  ```

- Traffic per user (bytes/s):
  ```promql
  sum by (user) (rate(strongswan_child_bytes_in_total[5m]))
  sum by (user) (rate(strongswan_child_bytes_out_total[5m]))
  ```

## Notes

- Connection history is captured via `ike-updown` events and stored in Prometheus time series. If the exporter restarts, counters reset and last timestamps are rebuilt from new events.
- For EAP users, the label `user` is derived from `remote-eap-id` (fallback to `remote-id`).
