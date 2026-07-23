package traefik

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func Configure(ctx context.Context, r runner.Runner, image string) error {
	return configureAt(ctx, r, image, "/var/lib/centralcloud-traefik")
}

func configureAt(ctx context.Context, r runner.Runner, image, dataDirectory string) error {
	if !strings.Contains(image, "@sha256:") {
		return errors.New("traefik image must be pinned by digest")
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
		image,
		"--providers.docker=true", "--providers.docker.exposedbydefault=false",
		"--entrypoints.web.address=:80", "--entrypoints.websecure.address=:443",
		"--certificatesresolvers.letsencrypt.acme.storage=/data/acme.json",
		"--certificatesresolvers.letsencrypt.acme.tlschallenge=true",
	}
	if _, err := r.Run(ctx, "docker", command...); err != nil {
		return fmt.Errorf("traefik run: %w", err)
	}
	return nil
}
