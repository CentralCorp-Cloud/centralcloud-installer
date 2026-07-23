package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHRuleComesFirstAndAgentIsRestricted(t *testing.T) {
	plan, err := Build("ufw", 2222, 9443, []string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Commands[0][2] != "2222/tcp" {
		t.Fatalf("SSH is not protected first: %#v", plan.Commands)
	}
	if _, err := Build("ufw", 0, 9443, []string{"203.0.113.0/24"}); err == nil {
		t.Fatal("expected missing SSH port to fail")
	}
}

func TestNFTPlanSupportsIPv4AndIPv6AndIsValidatedBeforeApply(t *testing.T) {
	plan, err := Build("nftables", 2222, 9443, []string{"203.0.113.0/24", "2001:db8::/48"})
	if err != nil {
		t.Fatal(err)
	}
	executor := &recordingRunner{}
	directory := t.TempDir()
	if err := applyAt(context.Background(), executor, plan, filepath.Join(directory, "ufw"), filepath.Join(directory, "nft")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "nft", "centralcloud-installer.nft"))
	if err != nil {
		t.Fatal(err)
	}
	rules := string(data)
	if !strings.Contains(rules, "control_plane_v4") || !strings.Contains(rules, "control_plane_v6") {
		t.Fatalf("missing dual-stack rules: %s", rules)
	}
	if len(executor.calls) != 4 ||
		executor.calls[0][1] != "-c" ||
		executor.calls[1][1] != "-c" ||
		executor.calls[2][0] != "systemctl" ||
		executor.calls[3][1] != "-f" {
		t.Fatalf("nft rules were not checked before apply: %#v", executor.calls)
	}
	mainConfig, err := os.ReadFile(filepath.Join(directory, "nftables.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mainConfig), `include "`) || !strings.Contains(string(mainConfig), "*.nft") {
		t.Fatalf("persistent nftables include is missing: %s", mainConfig)
	}
}

func TestUFWFailureRestoresRulesAndReloads(t *testing.T) {
	directory := t.TempDir()
	ufwDirectory := filepath.Join(directory, "ufw")
	if err := os.MkdirAll(ufwDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ufwDirectory, "user.rules")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &recordingRunner{
		failAt: 4,
		hook: func(call int) {
			if call == 3 {
				_ = os.WriteFile(path, []byte("changed\n"), 0o600)
			}
		},
	}
	plan := Plan{Backend: "ufw", Commands: [][]string{
		{"ufw", "allow", "2222/tcp"},
		{"ufw", "deny", "5432/tcp"},
	}}

	if err := applyAt(context.Background(), executor, plan, ufwDirectory, filepath.Join(directory, "nft")); err == nil {
		t.Fatal("expected firewall application to fail")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original\n" {
		t.Fatalf("rules were not rolled back: %q", data)
	}
	last := executor.calls[len(executor.calls)-1]
	if len(last) != 2 || last[0] != "ufw" || last[1] != "reload" {
		t.Fatalf("rollback did not reload UFW: %#v", executor.calls)
	}
}

type recordingRunner struct {
	calls  [][]string
	failAt int
	hook   func(int)
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	call := len(r.calls)
	if r.hook != nil {
		r.hook(call)
	}
	if call == r.failAt {
		return nil, errors.New("planned failure")
	}
	return nil, nil
}
