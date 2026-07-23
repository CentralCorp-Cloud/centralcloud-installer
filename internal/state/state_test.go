package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicStateAndIdempotentStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := Store{Path: path}
	value := State{
		InstallerVersion:     "1.0.0",
		Backups:              map[string]string{},
		MemoryBytes:          8 << 30,
		DiskBytes:            100 << 30,
		CompletionRequestKey: "7a59dfd2-9e4d-4abf-b5ae-351a82f111b9",
	}
	value.Complete("preflight")
	value.Complete("preflight")
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.CompletedSteps) != 1 {
		t.Fatalf("unexpected state: %#v %v", loaded, err)
	}
	if loaded.CompletionRequestKey != value.CompletionRequestKey ||
		loaded.MemoryBytes != value.MemoryBytes ||
		loaded.DiskBytes != value.DiskBytes {
		t.Fatalf("resumable completion metadata was not preserved: %#v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions: %v %v", info.Mode(), err)
	}
}
