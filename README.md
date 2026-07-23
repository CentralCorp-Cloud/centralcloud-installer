# CentralCloud Node Installer

The installer enrolls a fresh Debian or Ubuntu server with the CentralCloud
Dashboard, then reconciles Docker, PostgreSQL, Traefik, mTLS and the signed
Agent release.

```sh
curl -fsSL https://install.centralcloud.fr/node -o /tmp/centralcloud-node.sh
sudo bash /tmp/centralcloud-node.sh
```

Automatic mode reads a short-lived one-time token from a root-only file:

```sh
sudo centralcloud-installer install \
  --non-interactive \
  --token-file /run/secrets/centralcloud-enrollment-token \
  --delete-token-file
```

Commands are `install`, `status`, `doctor`, `repair`, `update`, `version` and
`uninstall`. Common options include `--api-url`, `--channel`, `--token-file`,
`--skip-firewall`, `--dry-run`, `--verbose`, `--config` and `--state-dir`.
The optional YAML configuration uses the equivalent snake_case keys (for
example `api_url`, `state_dir`, `minimum_memory_bytes` and `http_timeout`);
unknown keys are rejected and explicit CLI flags take priority.

Supported hosts are Debian 12/13 and Ubuntu 22.04/24.04 on amd64 or arm64 with
systemd. State is `/var/lib/centralcloud-installer/state.json` (`0600`). Agent
configuration and TLS are under `/etc/centralcloud-agent`; durable Agent data,
panels and backups are under `/var/lib/centralcloud-agent`.

`uninstall` is deliberately non-destructive: it never removes panel storage,
PostgreSQL databases, Docker volumes, Agent encrypted state, backups or TLS
keys. `repair` replays only incomplete idempotent stages.

The bootstrap trusts HTTPS plus the release checksum file hosted at the same
immutable GitHub Release. It never downloads a branch. Environments requiring
an additional trust root should mirror and sign the bootstrap and artefacts.
