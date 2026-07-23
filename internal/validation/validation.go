package validation

import (
	"context"
	"fmt"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

func Run(ctx context.Context, r runner.Runner) ([]Check, error) {
	checks := []struct {
		name string
		cmd  []string
	}{
		{"docker", []string{"docker", "info"}},
		{"traefik", []string{"docker", "inspect", "centralcloud-traefik"}},
		{"postgresql", []string{"pg_isready", "-h", "127.0.0.1", "-p", "5432"}},
		{"agent-config", []string{"centralcloud-agent", "validate-config", "--config", "/etc/centralcloud-agent/config.yaml"}},
		{"agent-service", []string{"systemctl", "is-active", "centralcloud-agent"}},
		{"agent-enabled", []string{"systemctl", "is-enabled", "centralcloud-agent"}},
	}
	result := make([]Check, 0, len(checks))
	for _, check := range checks {
		if _, err := r.Run(ctx, check.cmd[0], check.cmd[1:]...); err != nil {
			result = append(result, Check{Name: check.name, Status: "error"})
			return result, fmt.Errorf("VALIDATION_FAILED: %s: %w", check.name, err)
		}
		result = append(result, Check{Name: check.name, Status: "ok"})
	}
	return result, nil
}

func RunFinal(ctx context.Context, r runner.Runner) ([]Check, error) {
	result, err := Run(ctx, r)
	if err != nil {
		return result, err
	}
	const network = "centralcloud-installer-validation"
	_, _ = r.Run(ctx, "docker", "network", "rm", network)
	if _, err := r.Run(ctx, "docker", "network", "create", "--driver", "bridge", network); err != nil {
		return append(result, Check{Name: "docker-network", Status: "error"}), fmt.Errorf("VALIDATION_FAILED: docker-network: %w", err)
	}
	if _, err := r.Run(ctx, "docker", "network", "rm", network); err != nil {
		return append(result, Check{Name: "docker-network", Status: "error"}), fmt.Errorf("VALIDATION_FAILED: docker-network-cleanup: %w", err)
	}
	return append(result, Check{Name: "docker-network", Status: "ok"}), nil
}
