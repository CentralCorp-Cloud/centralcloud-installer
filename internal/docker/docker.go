package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Install(ctx context.Context, r runner.Runner) error {
	id, codename, err := osRelease()
	if err != nil {
		return err
	}
	commands := [][]string{
		{"install", "-m", "0755", "-d", "/etc/apt/keyrings"},
		{"curl", "-fsSL", "https://download.docker.com/linux/" + id + "/gpg", "-o", "/etc/apt/keyrings/docker.asc"},
		{"chmod", "a+r", "/etc/apt/keyrings/docker.asc"},
	}
	for _, command := range commands {
		if _, err := r.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("docker: %w", err)
		}
	}
	arch := runtime.GOARCH
	source := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n", arch, id, codename)
	if err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(source), 0o644); err != nil {
		return err
	}
	for _, command := range [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"},
	} {
		if _, err := r.Run(ctx, command[0], command[1:]...); err != nil {
			return fmt.Errorf("docker: %w", err)
		}
	}
	changed, err := configureDaemonAt("/etc/docker/daemon.json")
	if err != nil {
		return fmt.Errorf("docker daemon configuration: %w", err)
	}
	if _, err := r.Run(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	if changed {
		if _, err := r.Run(ctx, "systemctl", "restart", "docker"); err != nil {
			return fmt.Errorf("docker restart: %w", err)
		}
	}
	if _, err := r.Run(ctx, "docker", "info"); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	return nil
}

func configureDaemonAt(path string) (bool, error) {
	configuration := map[string]any{}
	mode := os.FileMode(0o644)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("daemon.json must be a regular file")
		}
		mode = info.Mode().Perm()
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return false, readErr
		}
		if len(data) > 1<<20 {
			return false, errors.New("daemon.json exceeds 1 MiB")
		}
		if unmarshalErr := json.Unmarshal(data, &configuration); unmarshalErr != nil {
			return false, fmt.Errorf("decode daemon.json: %w", unmarshalErr)
		}
	case os.IsNotExist(err):
	default:
		return false, err
	}
	if hosts, ok := configuration["hosts"].([]any); ok {
		for _, host := range hosts {
			if value, isString := host.(string); isString && strings.HasPrefix(value, "tcp://") {
				return false, errors.New("public Docker TCP API configuration is forbidden")
			}
		}
	}

	changed := false
	driver, _ := configuration["log-driver"].(string)
	if driver == "" {
		driver = "json-file"
		configuration["log-driver"] = driver
		changed = true
	}
	if driver == "json-file" {
		options, ok := configuration["log-opts"].(map[string]any)
		if !ok {
			options = map[string]any{}
			configuration["log-opts"] = options
			changed = true
		}
		for key, value := range map[string]string{"max-size": "10m", "max-file": "3"} {
			if _, exists := options[key]; !exists {
				options[key] = value
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}
	data, err := json.MarshalIndent(configuration, "", "  ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".centralcloud-docker-*")
	if err != nil {
		return false, err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return false, err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return false, err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return false, err
	}
	if err := temp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, path); err != nil {
		return false, err
	}
	return true, nil
}

func osRelease() (string, string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, `"' `)
		}
	}
	if (values["ID"] != "debian" && values["ID"] != "ubuntu") || values["VERSION_CODENAME"] == "" {
		return "", "", fmt.Errorf("unsupported Docker repository platform")
	}
	return values["ID"], values["VERSION_CODENAME"], nil
}
