package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/logging"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

type Plan struct {
	Backend     string
	SSHPort     uint16
	AgentPort   uint16
	SourceCIDRs []string
	Commands    [][]string
}

func Build(backend string, sshPort, agentPort uint16, cidrs []string) (Plan, error) {
	if sshPort == 0 {
		return Plan{}, errors.New("SSH_PROTECTION_FAILED: SSH port was not detected")
	}
	if agentPort == 0 || len(cidrs) == 0 {
		return Plan{}, errors.New("firewall requires Agent port and reverse-proxy network CIDRs")
	}
	for _, raw := range cidrs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return Plan{}, fmt.Errorf("invalid reverse-proxy network CIDR %q", raw)
		}
	}
	plan := Plan{Backend: backend, SSHPort: sshPort, AgentPort: agentPort, SourceCIDRs: append([]string(nil), cidrs...)}
	switch backend {
	case "ufw":
		plan.Commands = append(plan.Commands,
			[]string{"ufw", "allow", strconv.Itoa(int(sshPort)) + "/tcp", "comment", "CentralCloud SSH"},
			[]string{"ufw", "allow", "80/tcp", "comment", "CentralCloud HTTP"},
			[]string{"ufw", "allow", "443/tcp", "comment", "CentralCloud HTTPS"},
		)
		for _, cidr := range cidrs {
			plan.Commands = append(plan.Commands, []string{"ufw", "allow", "from", cidr, "to", "any", "port", strconv.Itoa(int(agentPort)), "proto", "tcp", "comment", "CentralCloud Agent"})
		}
		plan.Commands = append(plan.Commands, []string{"ufw", "deny", strconv.Itoa(int(agentPort)) + "/tcp", "comment", "CentralCloud Agent default deny"}, []string{"ufw", "deny", "5432/tcp", "comment", "CentralCloud PostgreSQL"})
		plan.Commands = append(plan.Commands, []string{"ufw", "--force", "enable"})
	case "nftables":
		plan.Commands = [][]string{{"nft", "-f", "/etc/nftables.d/centralcloud-installer.nft"}}
	default:
		return Plan{}, fmt.Errorf("unsupported firewall backend %q", backend)
	}
	return plan, nil
}

func DetectBackend(ctx context.Context, executor runner.Runner) (string, error) {
	if _, err := executor.Run(ctx, "ufw", "status"); err == nil {
		return "ufw", nil
	}
	if _, err := executor.Run(ctx, "nft", "--version"); err == nil {
		return "nftables", nil
	}
	return "", errors.New("no supported firewall backend is available")
}

func (p Plan) NFT() string {
	var sets, rules []string
	var ipv4, ipv6 []string
	for _, raw := range p.SourceCIDRs {
		prefix, _ := netip.ParsePrefix(raw)
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, raw)
		} else {
			ipv6 = append(ipv6, raw)
		}
	}
	if len(ipv4) > 0 {
		sets = append(sets, fmt.Sprintf("  set reverse_proxy_v4 { type ipv4_addr; flags interval; elements = { %s } }", strings.Join(ipv4, ", ")))
		rules = append(rules, fmt.Sprintf("    tcp dport %d ip saddr @reverse_proxy_v4 accept", p.AgentPort))
	}
	if len(ipv6) > 0 {
		sets = append(sets, fmt.Sprintf("  set reverse_proxy_v6 { type ipv6_addr; flags interval; elements = { %s } }", strings.Join(ipv6, ", ")))
		rules = append(rules, fmt.Sprintf("    tcp dport %d ip6 saddr @reverse_proxy_v6 accept", p.AgentPort))
	}
	return fmt.Sprintf(`table inet centralcloud_installer
flush table inet centralcloud_installer
table inet centralcloud_installer {
%s
  chain input { type filter hook input priority -5; policy accept;
%s
    tcp dport %d reject
    tcp dport 5432 reject
  }
}
`, strings.Join(sets, "\n"), strings.Join(rules, "\n"), p.AgentPort)
}

func Apply(ctx context.Context, executor runner.Runner, plan Plan) error {
	return applyAt(ctx, executor, plan, "/etc/ufw", "/etc/nftables.d")
}

func applyAt(ctx context.Context, executor runner.Runner, plan Plan, ufwDirectory, nftDirectory string) error {
	switch plan.Backend {
	case "ufw":
		for _, command := range plan.Commands {
			arguments := append([]string{"--dry-run"}, command[1:]...)
			if output, err := executor.Run(ctx, "ufw", arguments...); err != nil {
				return fmt.Errorf("validate firewall: %w", commandError("FIREWALL_VALIDATE_FAILED", append([]string{"ufw"}, arguments...), output, err))
			}
		}
		snapshots, err := snapshotFiles(filepath.Join(ufwDirectory, "user.rules"), filepath.Join(ufwDirectory, "user6.rules"))
		if err != nil {
			return err
		}
		for _, command := range plan.Commands {
			if output, err := executor.Run(ctx, command[0], command[1:]...); err != nil {
				failure := commandError("FIREWALL_APPLY_FAILED", command, output, err)
				restoreErr := restoreFiles(snapshots)
				_, reloadErr := executor.Run(ctx, "ufw", "reload")
				if restoreErr != nil {
					return fmt.Errorf("apply firewall: %w (rollback: %v)", failure, restoreErr)
				}
				if reloadErr != nil {
					return fmt.Errorf("apply firewall: %w (reload rollback: %v)", failure, reloadErr)
				}
				return fmt.Errorf("apply firewall: %w", failure)
			}
		}
		return nil
	case "nftables":
		path := filepath.Join(nftDirectory, "centralcloud-installer.nft")
		mainConfig := filepath.Join(filepath.Dir(nftDirectory), "nftables.conf")
		snapshots, err := snapshotFiles(path, mainConfig)
		if err != nil {
			return err
		}
		if err := atomicWrite(path, []byte(plan.NFT()), 0o600); err != nil {
			return err
		}
		if err := ensureNFTInclude(mainConfig, nftDirectory); err != nil {
			_ = restoreFiles(snapshots)
			return err
		}
		if _, err := executor.Run(ctx, "nft", "-c", "-f", path); err != nil {
			_ = restoreFiles(snapshots)
			return fmt.Errorf("validate firewall: %w", err)
		}
		if _, err := executor.Run(ctx, "nft", "-c", "-f", mainConfig); err != nil {
			_ = restoreFiles(snapshots)
			return fmt.Errorf("validate persistent firewall: %w", err)
		}
		if _, err := executor.Run(ctx, "systemctl", "enable", "nftables"); err != nil {
			_ = restoreFiles(snapshots)
			return fmt.Errorf("persist firewall: %w", err)
		}
		if _, err := executor.Run(ctx, "nft", "-f", path); err != nil {
			restoreErr := restoreFiles(snapshots)
			if restoreErr != nil {
				return fmt.Errorf("apply firewall: %w (rollback: %v)", err, restoreErr)
			}
			return fmt.Errorf("apply firewall: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported firewall backend %q", plan.Backend)
	}
}

func commandError(code string, command []string, output []byte, err error) error {
	diagnostic := safeDiagnostic(output)
	base := fmt.Sprintf("%s: command %q failed: %v", code, strings.Join(command, " "), err)
	if diagnostic == "" {
		return errors.New(base)
	}

	return fmt.Errorf("%s\nDiagnostic de la commande :\n%s", base, diagnostic)
}

func safeDiagnostic(output []byte) string {
	const maximumRunes = 4096

	clean := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || unicode.IsPrint(character) {
			return character
		}
		return -1
	}, string(output))
	clean = strings.TrimSpace(logging.Redact(clean))
	runes := []rune(clean)
	if len(runes) > maximumRunes {
		clean = "[sortie tronquée]\n" + string(runes[len(runes)-maximumRunes:])
	}

	return clean
}

func ensureNFTInclude(mainConfig, nftDirectory string) error {
	data, err := os.ReadFile(mainConfig)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	include := fmt.Sprintf("include %q", filepath.ToSlash(filepath.Join(nftDirectory, "*.nft")))
	if strings.Contains(string(data), include) {
		return nil
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(include+"\n")...)
	return atomicWrite(mainConfig, data, 0o644)
}

type fileSnapshot struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
}

func snapshotFiles(paths ...string) ([]fileSnapshot, error) {
	snapshots := make([]fileSnapshot, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			info, statErr := os.Stat(path)
			if statErr != nil {
				return nil, statErr
			}
			snapshots = append(snapshots, fileSnapshot{path: path, data: data, mode: info.Mode().Perm(), existed: true})
			continue
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		snapshots = append(snapshots, fileSnapshot{path: path, existed: false})
	}
	return snapshots, nil
}

func restoreFiles(snapshots []fileSnapshot) error {
	for _, snapshot := range snapshots {
		if !snapshot.existed {
			if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := atomicWrite(snapshot.path, snapshot.data, snapshot.mode); err != nil {
			return err
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".centralcloud-firewall-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { _ = os.Remove(name) }()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func DetectSSHPort(ctx context.Context, executor runner.Runner, environment string) (uint16, error) {
	fields := strings.Fields(environment)
	if len(fields) == 4 {
		port, err := strconv.ParseUint(fields[3], 10, 16)
		if err == nil && port > 0 {
			return uint16(port), nil
		}
	}
	output, err := executor.Run(ctx, "sshd", "-T")
	if err != nil {
		return 0, errors.New("SSH_PROTECTION_FAILED: unable to inspect sshd")
	}
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "port" {
			port, parseErr := strconv.ParseUint(parts[1], 10, 16)
			if parseErr == nil && port > 0 {
				return uint16(port), nil
			}
		}
	}
	return 0, errors.New("SSH_PROTECTION_FAILED: SSH port was not detected")
}
