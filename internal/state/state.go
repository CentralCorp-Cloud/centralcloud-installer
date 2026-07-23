package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const SchemaVersion = 1

type State struct {
	SchemaVersion         int               `json:"schema_version"`
	InstallerVersion      string            `json:"installer_version"`
	EnrollmentID          string            `json:"enrollment_id,omitempty"`
	NodeID                string            `json:"node_id,omitempty"`
	NodeName              string            `json:"node_name,omitempty"`
	NodeFQDN              string            `json:"node_fqdn,omitempty"`
	NodeEndpoint          string            `json:"node_endpoint,omitempty"`
	PanelDomainSuffix     string            `json:"panel_domain_suffix,omitempty"`
	AgentVersion          string            `json:"agent_version,omitempty"`
	AgentProtocol         string            `json:"agent_protocol,omitempty"`
	AgentManifestURL      string            `json:"agent_manifest_url,omitempty"`
	AllowedClientSANs     []string          `json:"allowed_client_sans,omitempty"`
	AllowedSourceCIDRs    []string          `json:"allowed_source_cidrs,omitempty"`
	MemoryBytes           uint64            `json:"memory_bytes,omitempty"`
	DiskBytes             uint64            `json:"disk_bytes,omitempty"`
	Step                  string            `json:"step"`
	CompletedSteps        []string          `json:"completed_steps"`
	CreatedFiles          []string          `json:"created_files"`
	Backups               map[string]string `json:"backups"`
	BootstrapToken        string            `json:"bootstrap_token,omitempty"`
	CertificateRequestKey string            `json:"certificate_request_key,omitempty"`
	CompletionRequestKey  string            `json:"completion_request_key,omitempty"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

type Store struct{ Path string }

func (s Store) Load() (State, error) {
	var value State
	data, err := os.ReadFile(s.Path) // #nosec G304 -- configured state path.
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("decode state: %w", err)
	}
	if value.SchemaVersion != SchemaVersion {
		return value, fmt.Errorf("unsupported state schema %d", value.SchemaVersion)
	}
	return value, nil
}

func (s Store) Save(value State) error {
	value.SchemaVersion = SchemaVersion
	value.UpdatedAt = time.Now().UTC()
	if value.Backups == nil {
		value.Backups = map[string]string{}
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(0o600); err != nil {
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
	return os.Rename(name, s.Path)
}

func (s *State) Complete(step string) {
	for _, current := range s.CompletedSteps {
		if current == step {
			s.Step = step
			return
		}
	}
	s.CompletedSteps = append(s.CompletedSteps, step)
	s.Step = step
}

func (s State) HasCompleted(step string) bool {
	for _, current := range s.CompletedSteps {
		if current == step {
			return true
		}
	}
	return false
}
