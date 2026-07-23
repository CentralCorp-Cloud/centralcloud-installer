package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Configuration struct {
	NodeID             string
	NodeName           string
	FQDN               string
	ListenAddress      string
	PanelDomainSuffix  string
	TokenSHA256        string
	MaximumDeployments int
}

func Configure(c Configuration) error {
	for path, mode := range map[string]os.FileMode{
		"/etc/centralcloud-agent":             0o750,
		"/etc/centralcloud-agent/secrets":     0o750,
		"/var/lib/centralcloud-agent":         0o700,
		"/var/lib/centralcloud-agent/backups": 0o700,
		"/var/lib/centralcloud-agent/panels":  0o700,
	} {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	if err := secretIfAbsent("/etc/centralcloud-agent/secrets/master.key", 32); err != nil {
		return err
	}
	if err := secretIfAbsent("/etc/centralcloud-agent/secrets/postgres_password", 48); err != nil {
		return err
	}
	digest, err := hex.DecodeString(c.TokenSHA256)
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("Agent bearer token SHA-256 digest is invalid")
	}
	if err := atomicWrite("/etc/centralcloud-agent/secrets/api_token.sha256", []byte(c.TokenSHA256+"\n"), 0o600); err != nil {
		return err
	}
	maximum := c.MaximumDeployments
	if maximum < 1 {
		maximum = 50
	}
	config := fmt.Sprintf(`node:
  id: %q
  name: %q
server:
  address: %q
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 60s
  operation_timeout: 10m
  max_request_bytes: 1048576
  rate_per_second: 10
  rate_burst: 20
security:
  mode: bearer
  token_sha256_file: /etc/centralcloud-agent/secrets/api_token.sha256
  behind_reverse_proxy: true
  master_key_file: /etc/centralcloud-agent/secrets/master.key
  allowed_client_sans: []
  allowed_source_cidrs: []
  timestamp_skew: 5m
docker:
  socket: unix:///var/run/docker.sock
  panel_image_repository: ghcr.io/centralcorp-cloud/centralpanel-cloud
  require_image_digest: true
  panel_user: "10001:10001"
  pids_limit: 256
postgres:
  host: 127.0.0.1
  port: 5432
  administrator_database: postgres
  administrator_username: centralcloud_provisioner
  administrator_password_file: /etc/centralcloud-agent/secrets/postgres_password
  backup_image: postgres:17-alpine
  panel_host: ""
traefik:
  container_name: centralcloud-traefik
  domain_suffix: %q
  entrypoint: websecure
  certificate_resolver: letsencrypt
limits:
  maximum_deployments: %d
  default_memory_bytes: 402653184
  default_cpu_limit: 0.5
  maximum_concurrent_operations: 4
panel:
  allowed_environment_keys: []
  install_command: ["php", "artisan", "auto:install", "--bootstrap-file=/run/secrets/panel_bootstrap.json", "--no-interaction"]
  migration_command: ["php", "artisan", "migrate", "--force", "--no-interaction"]
  admin_reset_command: ["php", "artisan", "panel:admin-reset", "--bootstrap-file=/run/secrets/panel_admin_reset.json", "--no-interaction"]
storage:
  database_file: /var/lib/centralcloud-agent/state.db
  runtime_directory: /run/centralcloud-agent
  backup_directory: /var/lib/centralcloud-agent/backups
  panel_directory: /var/lib/centralcloud-agent/panels
`, c.NodeID, c.NodeName, firstNonEmpty(c.ListenAddress, "127.0.0.1:9443"), firstNonEmpty(c.PanelDomainSuffix, domainSuffix(c.FQDN)), maximum)
	if err := atomicWrite("/etc/centralcloud-agent/config.yaml", []byte(config), 0o640); err != nil {
		return err
	}
	return atomicWrite("/etc/systemd/system/centralcloud-agent.service", []byte(systemdUnit), 0o644)
}

func secretIfAbsent(path string, bytes int) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("unsafe existing secret %s", path)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(value) + "\n")
	for index := range value {
		value[index] = 0
	}
	return atomicWrite(path, encoded, 0o600)
}

func atomicWrite(path string, value []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".centralcloud-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(value); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func yamlList(values []string) string {
	if len(values) == 0 {
		return "    []"
	}
	var lines []string
	for _, value := range values {
		lines = append(lines, fmt.Sprintf("    - %q", value))
	}
	return strings.Join(lines, "\n")
}

func domainSuffix(fqdn string) string {
	_, suffix, ok := strings.Cut(fqdn, ".")
	if !ok {
		return fqdn
	}
	return suffix
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const systemdUnit = `[Unit]
Description=CentralCloud Node Agent
Requires=docker.service postgresql.service
After=network-online.target docker.service postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=centralcloud-agent
Group=centralcloud-agent
SupplementaryGroups=docker
ExecStart=/usr/local/bin/centralcloud-agent serve --config /etc/centralcloud-agent/config.yaml
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/centralcloud-agent /run/centralcloud-agent

[Install]
WantedBy=multi-user.target
`
