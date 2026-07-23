package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ccagent "github.com/CentralCorp-Cloud/centralcloud-installer/internal/agent"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/config"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/detection"
	ccdocker "github.com/CentralCorp-Cloud/centralcloud-installer/internal/docker"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/enrollment"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/firewall"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/packages"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/postgresql"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/release"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/state"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/traefik"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/validation"
)

type App struct {
	Version          string
	Commit           string
	BuildDate        string
	Config           config.Config
	Runner           runner.Runner
	HTTP             *http.Client
	Log              *slog.Logger
	Output           func(string, ...any)
	TraefikImage     string
	ReleasePublicKey string
}

func (a App) Run(ctx context.Context) error {
	switch a.Config.Command {
	case "version":
		a.Output("centralcloud-installer %s commit=%s build_date=%s", a.Version, a.Commit, a.BuildDate)
		return nil
	case "install", "repair":
		return a.install(ctx)
	case "status":
		return a.status()
	case "doctor":
		_, err := validation.Run(ctx, a.Runner)
		return err
	case "update":
		return a.update(ctx)
	case "uninstall":
		return a.uninstall(ctx)
	default:
		return errors.New("unsupported command")
	}
}

func (a App) install(ctx context.Context) error {
	store := state.Store{Path: filepath.Join(a.Config.StateDir, "state.json")}
	current, err := store.Load()
	if err != nil {
		return err
	}
	if current.SchemaVersion == 0 {
		current = state.State{InstallerVersion: a.Version, Step: "preflight", Backups: map[string]string{}}
	}
	nonce, err := randomHex(24)
	if err != nil {
		return err
	}
	host, err := detection.Detect(a.Version, nonce, a.Config.MinimumMemory, a.Config.MinimumDisk)
	if err != nil {
		return err
	}
	host.Channel = a.Config.Channel
	current.MemoryBytes = host.MemoryBytes
	current.DiskBytes = host.DiskBytes
	a.Output("CentralCloud Node Installer v%s\n\n✓ %s %s détecté\n✓ Architecture linux/%s\n✓ %.1f GiB de mémoire\n✓ %.1f GiB de disque disponible", a.Version, host.OS, host.OSVersion, host.Architecture, float64(host.MemoryBytes)/(1<<30), float64(host.DiskBytes)/(1<<30))
	if a.Config.DryRun {
		a.Output("Dry-run: packages → Docker → PostgreSQL → Traefik/HTTPS → Agent Bearer → firewall → validation")
		return nil
	}
	if err := installSelf(); err != nil {
		return err
	}
	current.Complete("preflight")
	if err := store.Save(current); err != nil {
		return err
	}
	client := enrollment.Client{BaseURL: a.Config.APIURL, HTTP: a.HTTP, Clock: enrollment.RealClock{}}
	if current.EnrollmentID == "" || current.BootstrapToken == "" {
		token, cleanup, err := config.EnrollmentToken(a.Config)
		if err != nil {
			return err
		}
		var approved enrollment.Approved
		if len(token) > 0 {
			approved, err = client.Automatic(ctx, host, token)
			for index := range token {
				token[index] = 0
			}
			if err == nil {
				cleanup()
			}
		} else {
			if a.Config.NonInteractive {
				return errors.New("non-interactive installation requires --token-file or CENTRALCLOUD_ENROLLMENT_TOKEN")
			}
			auth, createErr := client.Create(ctx, host)
			if createErr != nil {
				return createErr
			}
			a.Output("\nCode d’association : %s\n\nOuvre :\n%s\n\nEn attente de validation...", auth.UserCode, auth.VerificationURI)
			approved, err = client.Poll(ctx, auth)
		}
		if err != nil {
			return err
		}
		current.EnrollmentID = approved.EnrollmentID
		current.NodeID = approved.Node.ID
		current.NodeName = approved.Node.Name
		current.NodeFQDN = approved.Node.FQDN
		current.NodeEndpoint = approved.Node.Endpoint
		current.PanelDomainSuffix = approved.Node.PanelDomainSuffix
		current.AgentVersion = approved.Agent.Version
		current.AgentProtocol = approved.Agent.ProtocolVersion
		current.AgentManifestURL = approved.Agent.ManifestURL
		if approved.Agent.Authentication.Mode != "bearer" {
			return errors.New("dashboard did not provide valid per-node bearer authentication")
		}
		current.AgentTokenSHA256, err = agentTokenSHA256(approved.Agent.Authentication.Token)
		if err != nil {
			return err
		}
		approved.Agent.Authentication.Token = ""
		current.BootstrapToken = approved.BootstrapToken
		current.Complete("waiting_for_claim")
		if err := store.Save(current); err != nil {
			return err
		}
		a.Output("✓ Node approuvé : %s", approved.Node.Name)
		return a.provision(ctx, client, store, current, approved, host)
	}
	var approved enrollment.Approved
	approved.EnrollmentID = current.EnrollmentID
	approved.BootstrapToken = current.BootstrapToken
	approved.Node.ID = current.NodeID
	approved.Node.Name = current.NodeName
	approved.Node.FQDN = current.NodeFQDN
	approved.Node.Endpoint = current.NodeEndpoint
	approved.Node.PanelDomainSuffix = current.PanelDomainSuffix
	approved.Agent.Version = current.AgentVersion
	approved.Agent.ProtocolVersion = current.AgentProtocol
	approved.Agent.ManifestURL = current.AgentManifestURL
	approved.Agent.Authentication.Mode = "bearer"
	a.Output("Reprise de l’installation du Node %s à l’étape %s", current.NodeName, current.Step)
	return a.provision(ctx, client, store, current, approved, host)
}

func (a App) provision(ctx context.Context, client enrollment.Client, store state.Store, current state.State, approved enrollment.Approved, host detection.Host) error {
	type stage struct {
		name    string
		percent int
		action  func() error
	}
	stages := []stage{
		{"packages", 12, func() error { return packages.Install(ctx, a.Runner) }},
		{"docker", 24, func() error { return ccdocker.Install(ctx, a.Runner) }},
		{"postgresql", 36, func() error { return postgresql.Configure(ctx, a.Runner) }},
		{"traefik", 48, func() error { return traefik.ConfigureAgent(ctx, a.Runner, a.TraefikImage, approved.Node.FQDN) }},
	}
	for index, item := range stages {
		if current.HasCompleted(item.name) {
			continue
		}
		a.Output("[%d/9] %s", index+1, item.name)
		key, _ := randomUUID()
		_ = client.Progress(ctx, current.EnrollmentID, current.BootstrapToken, key, item.name, item.percent, "Installation de "+item.name)
		if err := item.action(); err != nil {
			return err
		}
		current.Complete(item.name)
		if err := store.Save(current); err != nil {
			return err
		}
	}
	publicKey, err := release.PublicKey(firstNonEmpty(a.Config.PublicKey, a.ReleasePublicKey))
	if err != nil {
		return err
	}
	releases := release.Client{HTTP: a.HTTP, PublicKey: publicKey}
	manifest, err := releases.Fetch(ctx, approved.Agent.ManifestURL)
	if err != nil {
		return err
	}
	if err := release.CheckInstallerCompatibility(manifest, a.Version); err != nil {
		return err
	}
	if manifest.Version != approved.Agent.Version || manifest.ProtocolVersion != approved.Agent.ProtocolVersion {
		return errors.New("incompatible Agent manifest")
	}
	asset, ok := manifest.Assets["linux-"+host.Architecture]
	if !ok {
		return fmt.Errorf("architecture linux-%s absent from Agent manifest", host.Architecture)
	}
	if err := releases.InstallAsset(ctx, asset, "/usr/local/bin/centralcloud-agent"); err != nil {
		return err
	}
	if _, err := a.Runner.Run(ctx, "id", "centralcloud-agent"); err != nil {
		if _, err := a.Runner.Run(ctx, "useradd", "--system", "--home", "/var/lib/centralcloud-agent", "--shell", "/usr/sbin/nologin", "--groups", "docker", "centralcloud-agent"); err != nil {
			return err
		}
	}
	proxyGateway, err := traefik.NetworkGateway(ctx, a.Runner)
	if err != nil {
		return err
	}
	if err := ccagent.Configure(ccagent.Configuration{
		NodeID: current.NodeID, NodeName: approved.Node.Name, FQDN: approved.Node.FQDN,
		ListenAddress: net.JoinHostPort(proxyGateway, "9443"), TokenSHA256: current.AgentTokenSHA256,
		PanelDomainSuffix: approved.Node.PanelDomainSuffix,
	}); err != nil {
		return err
	}
	for _, command := range [][]string{
		{"usermod", "--append", "--groups", "docker", "centralcloud-agent"},
		{"chown", "-R", "centralcloud-agent:centralcloud-agent", "/var/lib/centralcloud-agent"},
		{"chown", "-R", "centralcloud-agent:centralcloud-agent", "/etc/centralcloud-agent/secrets"},
		{"chown", "root:centralcloud-agent", "/etc/centralcloud-agent"},
		{"chown", "root:centralcloud-agent", "/etc/centralcloud-agent/config.yaml"},
	} {
		if _, err := a.Runner.Run(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	if _, err := a.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if !a.Config.SkipFirewall {
		sshPort, err := firewall.DetectSSHPort(ctx, a.Runner, os.Getenv("SSH_CONNECTION"))
		if err != nil {
			return err
		}
		backend, err := firewall.DetectBackend(ctx, a.Runner)
		if err != nil {
			return err
		}
		proxyCIDR, err := traefik.NetworkCIDR(ctx, a.Runner)
		if err != nil {
			return err
		}
		plan, err := firewall.Build(backend, sshPort, 9443, []string{proxyCIDR})
		if err != nil {
			return err
		}
		if err := firewall.Apply(ctx, a.Runner, plan); err != nil {
			return err
		}
	}
	current.Complete("firewall")
	if _, err := a.Runner.Run(ctx, "systemctl", "enable", "--now", "centralcloud-agent"); err != nil {
		return err
	}
	current.Complete("agent")
	checks, err := validation.RunFinal(ctx, a.Runner)
	if err != nil {
		return err
	}
	current.Complete("validation")
	if current.CompletionRequestKey == "" {
		current.CompletionRequestKey, err = randomUUID()
		if err != nil {
			return err
		}
		if err := store.Save(current); err != nil {
			return err
		}
	}
	_, err = client.Complete(ctx, current.EnrollmentID, current.BootstrapToken, current.CompletionRequestKey, map[string]any{
		"agent_identity": current.NodeID, "agent_version": manifest.Version, "protocol_version": manifest.ProtocolVersion,
		"services":    map[string]string{"docker": "ok", "postgresql": "ok", "traefik": "ok", "agent": "ok"},
		"healthcheck": "ok",
		"resources": map[string]uint64{
			"memory_bytes": host.MemoryBytes,
			"disk_bytes":   host.DiskBytes,
		},
		"validations": checks,
	})
	if err != nil {
		return err
	}
	current.BootstrapToken = ""
	current.AgentTokenSHA256 = ""
	current.CompletionRequestKey = ""
	current.Complete("complete")
	return store.Save(current)
}

func (a App) status() error {
	current, err := (state.Store{Path: filepath.Join(a.Config.StateDir, "state.json")}).Load()
	if err != nil {
		return err
	}
	a.Output("step=%s node_id=%s agent_version=%s", current.Step, current.NodeID, current.AgentVersion)
	return nil
}

func (a App) update(ctx context.Context) error {
	if a.Config.ManifestURL == "" {
		return errors.New("--manifest-url is required for update")
	}
	key, err := release.PublicKey(firstNonEmpty(a.Config.PublicKey, a.ReleasePublicKey))
	if err != nil {
		return err
	}
	client := release.Client{HTTP: a.HTTP, PublicKey: key}
	manifest, err := client.Fetch(ctx, a.Config.ManifestURL)
	if err != nil {
		return err
	}
	asset, ok := manifest.Assets["linux-"+runtime.GOARCH]
	if !ok {
		return errors.New("architecture absent from manifest")
	}
	if err := client.InstallAsset(ctx, asset, "/usr/local/bin/centralcloud-agent"); err != nil {
		return err
	}
	_, err = a.Runner.Run(ctx, "systemctl", "restart", "centralcloud-agent")
	return err
}

func (a App) uninstall(ctx context.Context) error {
	a.Log.Warn("non-destructive uninstall preserves all data, databases, volumes, backups and Agent secrets")
	for _, command := range [][]string{{"systemctl", "disable", "--now", "centralcloud-agent"}, {"systemctl", "daemon-reload"}} {
		if _, err := a.Runner.Run(ctx, command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func agentTokenSHA256(token string) (string, error) {
	if len(token) < 32 {
		return "", errors.New("dashboard did not provide valid per-node bearer authentication")
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return strings.Join([]string{encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]}, "-"), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func installSelf() error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(source) // #nosec G304 -- current verified executable.
	if err != nil {
		return err
	}
	target := "/usr/local/bin/centralcloud-installer"
	temp, err := os.CreateTemp(filepath.Dir(target), ".centralcloud-installer-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(0o755); err != nil {
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
	return os.Rename(name, target)
}
