package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion   int              `json:"schema_version"`
	Component       string           `json:"component"`
	Version         string           `json:"version"`
	ProtocolVersion string           `json:"protocol_version"`
	PublishedAt     string           `json:"published_at"`
	Assets          map[string]Asset `json:"assets"`
	Compatibility   struct {
		MinimumDashboardVersion string `json:"minimum_dashboard_version"`
		MinimumInstallerVersion string `json:"minimum_installer_version"`
	} `json:"compatibility"`
}

type Client struct {
	HTTP      *http.Client
	PublicKey ed25519.PublicKey
}

func CheckInstallerCompatibility(manifest Manifest, installerVersion string) error {
	minimum := manifest.Compatibility.MinimumInstallerVersion
	if minimum == "" {
		return errors.New("MANIFEST_INVALID: minimum_installer_version is required")
	}
	currentParts, err := semanticVersion(installerVersion)
	if err != nil {
		return fmt.Errorf("MANIFEST_INVALID: installer version: %w", err)
	}
	minimumParts, err := semanticVersion(minimum)
	if err != nil {
		return fmt.Errorf("MANIFEST_INVALID: minimum installer version: %w", err)
	}
	for index := range currentParts {
		if currentParts[index] > minimumParts[index] {
			return nil
		}
		if currentParts[index] < minimumParts[index] {
			return fmt.Errorf("INCOMPATIBLE_COMPONENT: installer %s is older than required %s", installerVersion, minimum)
		}
	}
	return nil
}

func semanticVersion(value string) ([3]int, error) {
	var result [3]int
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	core, _, _ := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) != len(result) {
		return result, fmt.Errorf("%q is not semantic version x.y.z", value)
	}
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return result, fmt.Errorf("%q is not semantic version x.y.z", value)
		}
		result[index] = number
	}
	return result, nil
}

func PublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode release public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("release public key must be 32 bytes")
	}
	return ed25519.PublicKey(raw), nil
}

func (c Client) Fetch(ctx context.Context, manifestURL string) (Manifest, error) {
	var manifest Manifest
	data, err := c.get(ctx, manifestURL, 1<<20)
	if err != nil {
		return manifest, err
	}
	signatureData, err := c.get(ctx, manifestURL+".sig", 4096)
	if err != nil {
		return manifest, err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureData)))
	if err != nil || !ed25519.Verify(c.PublicKey, data, signature) {
		return manifest, errors.New("SIGNATURE_INVALID: Agent manifest signature is invalid")
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("MANIFEST_INVALID: %w", err)
	}
	if manifest.SchemaVersion != 1 || manifest.Component != "centralcloud-agent" || manifest.Version == "" || manifest.ProtocolVersion == "" {
		return manifest, errors.New("MANIFEST_INVALID: required fields are missing")
	}
	return manifest, nil
}

func (c Client) InstallAsset(ctx context.Context, asset Asset, target string) error {
	if !strings.HasPrefix(asset.URL, "https://") || len(asset.SHA256) != 64 {
		return errors.New("MANIFEST_INVALID: insecure or incomplete asset")
	}
	data, err := c.get(ctx, asset.URL, 256<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), asset.SHA256) {
		return errors.New("CHECKSUM_MISMATCH: downloaded Agent does not match manifest")
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".centralcloud-agent-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(0o755); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
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
	backup := target + ".previous"
	if _, err := os.Stat(target); err == nil {
		_ = os.Remove(backup)
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(name, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	return nil
}

func (c Client) get(ctx context.Context, url string, maximum int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("download exceeds maximum size")
	}
	return data, nil
}
