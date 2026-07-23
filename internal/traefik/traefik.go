package traefik

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Configure(ctx context.Context, r runner.Runner, image string) error {
	return configureAt(ctx, r, image, "/var/lib/centralcloud-traefik")
}

func configureAt(ctx context.Context, r runner.Runner, image, dataDirectory string) error {
	return configureAgentAt(ctx, r, image, dataDirectory, "")
}

func ConfigureAgent(ctx context.Context, r runner.Runner, image, fqdn string) error {
	return configureAgentAt(ctx, r, image, "/var/lib/centralcloud-traefik", fqdn)
}

func configureAgentAt(ctx context.Context, r runner.Runner, image, dataDirectory, fqdn string) error {
	if !strings.Contains(image, "@sha256:") {
		return errors.New("traefik image must be pinned by digest")
	}
	if fqdn != "" && !hostnameRE.MatchString(strings.ToLower(fqdn)) {
		return errors.New("agent FQDN is invalid")
	}
	if info, err := os.Lstat(dataDirectory); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("traefik data path must be a real directory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dataDirectory, 0o700); err != nil {
		return err
	}
	acmePath := filepath.Join(dataDirectory, "acme.json")
	if info, err := os.Lstat(acmePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("traefik ACME storage must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if file, err := os.OpenFile(acmePath, os.O_CREATE|os.O_WRONLY, 0o600); err != nil {
		return err
	} else if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(acmePath, 0o600); err != nil {
		return err
	}
	if fqdn != "" {
		dynamicDirectory := filepath.Join(dataDirectory, "dynamic")
		if err := os.MkdirAll(dynamicDirectory, 0o700); err != nil {
			return err
		}
		dynamic := fmt.Sprintf(`http:
  routers:
    centralcloud-agent:
      rule: "Host(%s)"
      entryPoints: [websecure]
      service: centralcloud-agent
      tls:
        certResolver: letsencrypt
  services:
    centralcloud-agent:
      loadBalancer:
        servers:
          - url: "http://host.docker.internal:9443"
`, "`"+strings.ToLower(fqdn)+"`")
		if err := os.WriteFile(filepath.Join(dynamicDirectory, "agent.yml"), []byte(dynamic), 0o600); err != nil {
			return err
		}
	}

	if _, err := r.Run(ctx, "docker", "network", "inspect", "centralcloud-traefik"); err != nil {
		if _, createErr := r.Run(ctx, "docker", "network", "create", "centralcloud-traefik"); createErr != nil {
			return fmt.Errorf("traefik network: %w", createErr)
		}
	}
	if _, err := r.Run(ctx, "docker", "pull", image); err != nil {
		return fmt.Errorf("traefik pull: %w", err)
	}
	currentImage, inspectErr := r.Run(ctx, "docker", "inspect", "--format", "{{.Config.Image}}", "centralcloud-traefik")
	if inspectErr == nil {
		if strings.TrimSpace(string(currentImage)) != image {
			return errors.New("existing centralcloud-traefik container uses an incompatible image; run doctor before repair")
		}
		if fqdn != "" {
			profile, err := r.Run(ctx, "docker", "inspect", "--format", "{{index .Config.Labels \"centralcloud.installer.profile\"}}", "centralcloud-traefik")
			if err != nil || strings.TrimSpace(string(profile)) != "bearer-v1" {
				return errors.New("existing centralcloud-traefik container does not expose the bearer Agent route; preserve it under a backup name before running repair")
			}
		}
		if _, err := r.Run(ctx, "docker", "start", "centralcloud-traefik"); err != nil {
			return fmt.Errorf("traefik start: %w", err)
		}
		return nil
	}

	command := []string{
		"run", "--detach", "--name", "centralcloud-traefik", "--restart", "unless-stopped",
		"--network", "centralcloud-traefik", "--publish", "80:80", "--publish", "443:443",
		"--volume", "/var/run/docker.sock:/var/run/docker.sock:ro",
		"--volume", dataDirectory + ":/data",
		"--read-only", "--security-opt", "no-new-privileges:true",
		"--log-opt", "max-size=10m", "--log-opt", "max-file=3",
	}
	if fqdn != "" {
		command = append(command,
			"--label", "centralcloud.installer.profile=bearer-v1",
			"--add-host", "host.docker.internal:host-gateway",
			"--volume", filepath.Join(dataDirectory, "dynamic")+":/etc/traefik/dynamic:ro",
		)
	}
	command = append(command,
		image,
		"--providers.docker=true", "--providers.docker.exposedbydefault=false",
		"--entrypoints.web.address=:80", "--entrypoints.websecure.address=:443",
		"--certificatesresolvers.letsencrypt.acme.storage=/data/acme.json",
		"--certificatesresolvers.letsencrypt.acme.tlschallenge=true",
	)
	if fqdn != "" {
		command = append(command, "--providers.file.directory=/etc/traefik/dynamic", "--providers.file.watch=true")
	}
	if _, err := r.Run(ctx, "docker", command...); err != nil {
		return fmt.Errorf("traefik run: %w", err)
	}
	return nil
}

func NetworkCIDR(ctx context.Context, r runner.Runner) (string, error) {
	output, err := r.Run(ctx, "docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", "centralcloud-traefik")
	if err != nil {
		return "", fmt.Errorf("inspect Traefik network: %w", err)
	}
	cidr := strings.TrimSpace(string(output))
	if cidr == "" {
		return "", errors.New("traefik network has no subnet")
	}
	return cidr, nil
}

func NetworkGateway(ctx context.Context, r runner.Runner) (string, error) {
	output, err := r.Run(ctx, "docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", "centralcloud-traefik")
	if err != nil {
		return "", fmt.Errorf("inspect Traefik network gateway: %w", err)
	}
	gateway := strings.TrimSpace(string(output))
	if gateway == "" {
		return "", errors.New("traefik network has no gateway")
	}
	if _, err := netip.ParseAddr(gateway); err != nil {
		return "", errors.New("traefik network gateway is not a valid IP address")
	}
	return gateway, nil
}

var hostnameRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
