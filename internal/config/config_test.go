package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTokenFilePermissionsAndDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("0123456789012345678901234567890123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, cleanup, err := EnrollmentToken(Config{TokenFile: path, DeleteTokenFile: true})
	if err != nil || len(token) < 32 {
		t.Fatalf("token: %v", err)
	}
	if string(token) != "0123456789012345678901234567890123456789" {
		t.Fatalf("token whitespace was not normalized: %q", token)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file was not deleted")
	}
}

func TestEnrollmentTokenRejectsEmbeddedHeaderCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	value := "0123456789012345678901234567890123456789\nAuthorization: injected"
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnrollmentToken(Config{TokenFile: path}); err == nil {
		t.Fatal("token containing an embedded header was accepted")
	}
}

func TestTokenFileRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("0123456789012345678901234567890123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnrollmentToken(Config{TokenFile: path}); err == nil {
		t.Fatal("expected unsafe permissions to fail")
	}
}

func TestConfigFileIsStrictAndCLIHasPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte("api_url: https://dashboard.example.test\nchannel: beta\nskip_firewall: true\nhttp_timeout: 45s\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := Parse([]string{"install", "--config", path, "--channel", "stable"})
	if err != nil {
		t.Fatal(err)
	}
	if value.APIURL != "https://dashboard.example.test" || value.Channel != "stable" ||
		!value.SkipFirewall || value.HTTPTimeout.String() != "45s" {
		t.Fatalf("unexpected merged config: %#v", value)
	}

	if err := os.WriteFile(path, []byte("unknown_setting: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"install", "--config", path}); err == nil {
		t.Fatal("unknown YAML key was accepted")
	}
}

func TestConfigRejectsInsecureDashboardURL(t *testing.T) {
	if _, err := Parse([]string{"install", "--api-url", "http://dashboard.example.test"}); err == nil {
		t.Fatal("insecure Dashboard URL was accepted")
	}
}
