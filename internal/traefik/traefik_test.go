package traefik

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureCreatesPinnedTraefikWithPersistentACMEStorage(t *testing.T) {
	image := "traefik:v3.4.4@sha256:" + strings.Repeat("a", 64)
	executor := &fakeRunner{failNetworkInspect: true, failContainerInspect: true}
	directory := t.TempDir()

	if err := configureAt(context.Background(), executor, image, directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "acme.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ACME storage mode is %o", info.Mode().Perm())
	}
	joined := strings.Join(executor.calls, "\n")
	for _, expected := range []string{
		"docker network create centralcloud-traefik",
		"docker pull " + image,
		"--certificatesresolvers.letsencrypt.acme.tlschallenge=true",
		directory + ":/data",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in calls:\n%s", expected, joined)
		}
	}
}

func TestConfigureAgentCreatesHTTPSRouteWithoutPublishingAgentPort(t *testing.T) {
	image := "traefik:v3.4.4@sha256:" + strings.Repeat("a", 64)
	executor := &fakeRunner{failNetworkInspect: true, failContainerInspect: true}
	directory := t.TempDir()

	if err := configureAgentAt(context.Background(), executor, image, directory, "node-01.nodes.example.com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "dynamic", "agent.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "node-01.nodes.example.com") || !strings.Contains(string(data), "host.docker.internal:9443") {
		t.Fatalf("unexpected dynamic Agent route:\n%s", data)
	}
	joined := strings.Join(executor.calls, "\n")
	for _, expected := range []string{"--publish 443:443", "--add-host host.docker.internal:host-gateway", "--providers.file.directory=/etc/traefik/dynamic"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in calls:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "--publish 9443:9443") {
		t.Fatalf("Agent port was published: %s", joined)
	}
}

func TestConfigureDoesNotReplaceAnExistingIncompatibleContainer(t *testing.T) {
	image := "traefik:v3.4.4@sha256:" + strings.Repeat("a", 64)
	executor := &fakeRunner{containerImage: "traefik:v3.3@sha256:" + strings.Repeat("b", 64)}

	if err := configureAt(context.Background(), executor, image, t.TempDir()); err == nil {
		t.Fatal("expected incompatible managed container to fail")
	}
	for _, call := range executor.calls {
		if strings.Contains(call, "docker rm") || strings.Contains(call, "docker run") {
			t.Fatalf("existing container was changed: %s", call)
		}
	}
}

func TestConfigureRejectsSymlinkedSensitivePaths(t *testing.T) {
	image := "traefik:v3.4.4@sha256:" + strings.Repeat("a", 64)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "data")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := configureAt(context.Background(), &fakeRunner{}, image, link); err == nil {
		t.Fatal("expected symlinked data path to fail")
	}

	data := filepath.Join(root, "real-data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(data, "acme.json")); err != nil {
		t.Fatal(err)
	}
	if err := configureAt(context.Background(), &fakeRunner{}, image, data); err == nil {
		t.Fatal("expected symlinked ACME storage to fail")
	}
}

func TestNetworkGatewayReturnsValidatedDockerGateway(t *testing.T) {
	executor := &fakeRunner{networkGateway: "172.23.0.1\n"}
	gateway, err := NetworkGateway(context.Background(), executor)
	if err != nil {
		t.Fatal(err)
	}
	if gateway != "172.23.0.1" {
		t.Fatalf("unexpected gateway %q", gateway)
	}

	executor.networkGateway = "not-an-address"
	if _, err := NetworkGateway(context.Background(), executor); err == nil {
		t.Fatal("expected invalid gateway to fail")
	}
}

type fakeRunner struct {
	calls                []string
	failNetworkInspect   bool
	failContainerInspect bool
	containerImage       string
	networkGateway       string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if call == "docker network inspect centralcloud-traefik" && r.failNetworkInspect {
		return nil, errors.New("not found")
	}
	if strings.Contains(call, "{{(index .IPAM.Config 0).Gateway}}") {
		return []byte(r.networkGateway), nil
	}
	if strings.HasPrefix(call, "docker inspect --format") {
		if r.failContainerInspect {
			return nil, errors.New("not found")
		}
		return []byte(r.containerImage + "\n"), nil
	}
	return nil, nil
}
