package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/config"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func TestPersistentTLSMaterialReusesPrivateKeyAndCSR(t *testing.T) {
	directory := t.TempDir()
	privateKeyPath := filepath.Join(directory, "tls", "server.key")
	csrPath := filepath.Join(directory, "state", "node.csr")

	first, err := persistentTLSMaterial(
		"123e4567-e89b-42d3-a456-426614174000",
		"node.example.com",
		privateKeyPath,
		csrPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := persistentTLSMaterial(
		"123e4567-e89b-42d3-a456-426614174000",
		"node.example.com",
		privateKeyPath,
		csrPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.PrivateKeyPEM, second.PrivateKeyPEM) {
		t.Fatal("private key changed during resume")
	}
	if !bytes.Equal(first.CSRPEM, second.CSRPEM) {
		t.Fatal("CSR changed during resume")
	}
	for path, expected := range map[string]os.FileMode{
		privateKeyPath: 0o600,
		csrPath:        0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("%s permissions are %o", path, info.Mode().Perm())
		}
	}
}

func TestUninstallOnlyStopsAgentAndPreservesData(t *testing.T) {
	executor := &runner.Fake{}
	app := App{
		Config: config.Config{Command: "uninstall"},
		Runner: executor,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Output: func(string, ...any) {},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.Calls) != 2 {
		t.Fatalf("unexpected uninstall calls: %#v", executor.Calls)
	}
	for _, call := range executor.Calls {
		joined := strings.Join(call, " ")
		for _, destructive := range []string{"rm", "docker volume", "dropdb", "postgres"} {
			if strings.Contains(joined, destructive) {
				t.Fatalf("destructive uninstall command: %s", joined)
			}
		}
	}
}
