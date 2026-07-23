package docker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureDaemonPreservesSettingsAndAddsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker", "daemon.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"storage-driver":"overlay2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := configureDaemonAt(path)
	if err != nil || !changed {
		t.Fatalf("configure daemon: changed=%v err=%v", changed, err)
	}
	var configuration map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &configuration); err != nil {
		t.Fatal(err)
	}
	if configuration["storage-driver"] != "overlay2" || configuration["log-driver"] != "json-file" {
		t.Fatalf("settings were not preserved: %#v", configuration)
	}
	options, ok := configuration["log-opts"].(map[string]any)
	if !ok || options["max-size"] != "10m" || options["max-file"] != "3" {
		t.Fatalf("rotation is missing: %#v", configuration)
	}
	changed, err = configureDaemonAt(path)
	if err != nil || changed {
		t.Fatalf("second reconciliation is not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestConfigureDaemonRejectsTCPAPIAndSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "daemon.json")
	if err := os.WriteFile(path, []byte(`{"hosts":["tcp://0.0.0.0:2375"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := configureDaemonAt(path); err == nil {
		t.Fatal("Docker TCP API was accepted")
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := configureDaemonAt(path); err == nil {
		t.Fatal("symlinked daemon.json was accepted")
	}
}
