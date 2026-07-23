# Operations

`status` reads the local resumable state. `doctor` performs read-only Docker,
Traefik, PostgreSQL, Agent, configuration, permission, port and health checks.
`repair` resumes the first incomplete stage with the same enrollment, node
identity, private key and CSR. `update` requires an exact signed manifest URL,
performs an atomic Agent replacement and retains the previous binary for
rollback.

The PostgreSQL stage creates and removes a temporary database. Final validation
also creates and removes an isolated Docker network. These probes verify the
real provisioning capabilities without changing customer databases, panels or
volumes.

Sensitive paths:

- `/etc/centralcloud-agent/tls/server.key`
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

`uninstall` stops and disables the Agent but preserves all configuration,
certificates, encrypted state, panels, databases, volumes and backups.
