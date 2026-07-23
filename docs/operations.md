# Operations

`status` reads the local resumable state. `doctor` performs read-only Docker,
Traefik, PostgreSQL, Agent, configuration, permission, port and health checks.
`repair` resumes the first incomplete stage with the same enrollment, node
identity and bearer digest. `update` requires an exact signed manifest URL,
performs an atomic Agent replacement and retains the previous binary for
rollback.

The PostgreSQL stage creates and removes a temporary database. Final validation
also creates and removes an isolated Docker network. These probes verify the
real provisioning capabilities without changing customer databases, panels or
volumes.

Sensitive paths:

- `/etc/centralcloud-agent/secrets/api_token.sha256` (digest non réversible)
- `/etc/centralcloud-agent/secrets/master.key`
- `/etc/centralcloud-agent/secrets/postgres_password`
- `/var/lib/centralcloud-traefik/acme.json`
- `/var/lib/centralcloud-installer/state.json` while bootstrap is active

All are mode `0600`. The transient bootstrap token is removed from state after
finalization. Logs are structured and redact tokens, passwords, keys and
Authorization values.

Firewall changes first preserve the detected SSH port. UFW configuration is
applied in dry-run mode before activation and its rule files are restored if
reload fails. The nftables backend syntax-checks a dedicated transaction before
applying it, registers a persistent include with the nftables service and
restores the previous CentralCloud rules on failure.

Docker daemon settings are merged with the existing JSON configuration.
Existing storage and runtime choices are preserved, Docker's TCP API is
rejected, and the default `json-file` driver receives bounded rotation.

On failure, correct the reported stable error code and run:

```sh
sudo centralcloud-installer repair
```

An existing pre-`bearer-v1` Traefik container is never replaced silently.
Preserve it under a backup name before migration, then let `repair` create the
new profile without deleting its ACME data:

```sh
sudo docker stop centralcloud-traefik
sudo docker rename centralcloud-traefik centralcloud-traefik-mtls-backup
sudo centralcloud-installer repair
```

Keep the stopped backup until HTTPS validation succeeds.

`uninstall` stops and disables the Agent but preserves all configuration,
secrets, encrypted state, panels, databases, volumes and backups.
