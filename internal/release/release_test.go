package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignedManifest(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	manifest := []byte(`{"schema_version":1,"component":"centralcloud-agent","version":"1.2.0","protocol_version":"1","published_at":"2026-07-23T00:00:00Z","assets":{"linux-amd64":{"url":"https://example.test/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"compatibility":{"minimum_dashboard_version":"1.0.0","minimum_installer_version":"1.0.0"}}`)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, manifest))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json.sig" {
			_, _ = w.Write([]byte(signature))
			return
		}
		_, _ = w.Write(manifest)
	}))
	defer server.Close()
	value, err := (Client{HTTP: server.Client(), PublicKey: public}).Fetch(context.Background(), server.URL+"/manifest.json")
	if err != nil || value.Version != "1.2.0" {
		t.Fatalf("manifest: %#v %v", value, err)
	}
}

func TestInvalidManifestSignature(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json.sig" {
			_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))))
			return
		}
		_, _ = w.Write([]byte(`{"schema_version":1}`))
	}))
	defer server.Close()
	if _, err := (Client{HTTP: server.Client(), PublicKey: public}).Fetch(context.Background(), server.URL+"/manifest.json"); err == nil {
		t.Fatal("expected invalid signature")
	}
}

func TestInstallerCompatibility(t *testing.T) {
	manifest := Manifest{}
	manifest.Compatibility.MinimumInstallerVersion = "1.2.0"
	if err := CheckInstallerCompatibility(manifest, "1.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckInstallerCompatibility(manifest, "1.1.9"); err == nil {
		t.Fatal("expected an older installer to be rejected")
	}
	if err := CheckInstallerCompatibility(manifest, "dev"); err == nil {
		t.Fatal("expected non-versioned stable installer to be rejected")
	}
}
