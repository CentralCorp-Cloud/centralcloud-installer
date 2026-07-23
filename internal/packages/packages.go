package packages

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/logging"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Install(ctx context.Context, r runner.Runner) error {
	commands := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "curl", "gnupg", "jq", "nftables", "ufw"},
		{"install", "-m", "0755", "-d", "/etc/apt/keyrings"},
		{"curl", "-fsSL", "https://www.postgresql.org/media/keys/ACCC4CF8.asc", "-o", "/etc/apt/keyrings/postgresql.asc"},
		{"chmod", "0644", "/etc/apt/keyrings/postgresql.asc"},
	}
	for _, command := range commands {
		if err := run(ctx, r, command); err != nil {
			return err
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
		if err := run(ctx, r, command); err != nil {
			return err
		}
	}
	return nil
}

func run(ctx context.Context, r runner.Runner, command []string) error {
	output, err := r.Run(ctx, command[0], command[1:]...)
	if err == nil {
		return nil
	}

	diagnostic := safeDiagnostic(output)
	if diagnostic == "" {
		return fmt.Errorf("PACKAGES_COMMAND_FAILED: packages: %s: %w", strings.Join(command, " "), err)
	}

	return fmt.Errorf(
		"PACKAGES_COMMAND_FAILED: packages: %s: %w\nDiagnostic de la commande :\n%s",
		strings.Join(command, " "),
		err,
		diagnostic,
	)
}

func safeDiagnostic(output []byte) string {
	const maximumRunes = 4096

	clean := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || unicode.IsPrint(character) {
			return character
		}
		return -1
	}, string(output))
	clean = strings.TrimSpace(logging.Redact(clean))
	runes := []rune(clean)
	if len(runes) > maximumRunes {
		clean = "[sortie tronquée]\n" + string(runes[len(runes)-maximumRunes:])
	}

	return clean
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
