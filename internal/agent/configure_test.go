package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretIfAbsentReportsUnsafePathWithoutRedactionTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("not-a-real-key"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := secretIfAbsent(path, 32)
	if err == nil {
		t.Fatal("secretIfAbsent() error = nil, want unsafe permissions")
	}
	for _, expected := range []string{"AGENT_SECRET_UNSAFE", path, "current mode"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("secretIfAbsent() error = %q, want %q", err, expected)
		}
	}
}

func TestSecretIfAbsentPreservesSafeExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	const existing = "existing-key-material"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := secretIfAbsent(path, 32); err != nil {
		t.Fatalf("secretIfAbsent() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatal("secretIfAbsent() replaced an existing protected file")
	}
}
