//go:build integration

package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/release"
)

func TestSignedReleaseDownloadAndAtomicInstallation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assetBody := []byte("#!/bin/sh\nexit 0\n")
	checksum := sha256.Sum256(assetBody)
	var manifestBody []byte
	var signatureBody []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/manifest.json":
			_, _ = response.Write(manifestBody)
		case "/manifest.json.sig":
			_, _ = response.Write(signatureBody)
		case "/centralcloud-agent":
			_, _ = response.Write(assetBody)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	manifest := release.Manifest{
		SchemaVersion:   1,
		Component:       "centralcloud-agent",
		Version:         "1.3.0",
		ProtocolVersion: "1",
		PublishedAt:     "2026-07-23T00:00:00Z",
		Assets: map[string]release.Asset{
			"linux-amd64": {
				URL:    server.URL + "/centralcloud-agent",
				SHA256: hex.EncodeToString(checksum[:]),
			},
		},
	}
	manifestBody, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signatureBody = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestBody)))

	client := release.Client{HTTP: server.Client(), PublicKey: publicKey}
	loaded, err := client.Fetch(context.Background(), server.URL+"/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "centralcloud-agent")
	if err := client.InstallAsset(context.Background(), loaded.Assets["linux-amd64"], target); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(target) // #nosec G304 -- isolated integration-test path.
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != string(assetBody) {
		t.Fatal("installed asset differs from the signed manifest")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("installed mode is %o", info.Mode().Perm())
	}
}
