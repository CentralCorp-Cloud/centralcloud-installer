package packages

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Install(ctx context.Context, r runner.Runner) error {
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "curl", "gnupg", "jq", "nftables", "ufw"},
		{"install", "-m", "0755", "-d", "/etc/apt/keyrings"},
		{"curl", "-fsSL", "https://www.postgresql.org/media/keys/ACCC4CF8.asc", "-o", "/etc/apt/keyrings/postgresql.asc"},
	}
	for _, command := range commands {
		if _, err := r.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("packages: %w", err)
		}
	}
	codename, err := osCodename()
	if err != nil {
		return err
	}
	source := fmt.Sprintf("deb [signed-by=/etc/apt/keyrings/postgresql.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg main\n", codename)
	if err := os.WriteFile("/etc/apt/sources.list.d/pgdg.list", []byte(source), 0o644); err != nil {
		return err
	}
	for _, command := range [][]string{{"apt-get", "update"}, {"apt-get", "install", "-y", "--no-install-recommends", "postgresql-17", "postgresql-client-17"}} {
		if _, err := r.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("packages: %w", err)
		}
	}
	return nil
}

func osCodename() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "VERSION_CODENAME" {
			value = strings.Trim(value, `"' `)
			if value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("VERSION_CODENAME is missing")
}
