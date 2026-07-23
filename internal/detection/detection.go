package detection

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type Host struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os_version"`
	Architecture string   `json:"architecture"`
	MemoryBytes  uint64   `json:"memory_bytes"`
	DiskBytes    uint64   `json:"disk_bytes"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Installer    string   `json:"installer_version"`
	Nonce        string   `json:"nonce"`
	Channel      string   `json:"requested_channel,omitempty"`
}

func ParseOSRelease(r io.Reader) (string, string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	id, version := values["ID"], values["VERSION_ID"]
	if !SupportedOS(id, version) {
		return id, version, fmt.Errorf("UNSUPPORTED_OS: %s %s", id, version)
	}
	return id, version, nil
}

func SupportedOS(id, version string) bool {
	return (id == "debian" && (version == "12" || version == "13")) ||
		(id == "ubuntu" && (version == "22.04" || version == "24.04"))
}

func Architecture(value string) (string, error) {
	switch value {
	case "amd64":
		return "amd64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("UNSUPPORTED_ARCH: %s", value)
	}
}

func Detect(version, nonce string, minimumMemory, minimumDisk uint64) (Host, error) {
	if os.Geteuid() != 0 {
		return Host{}, errors.New("ROOT_REQUIRED: install must run as root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return Host{}, errors.New("SYSTEMD_REQUIRED: systemd is not running")
	}
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return Host{}, err
	}
	defer func() { _ = file.Close() }()
	id, osVersion, err := ParseOSRelease(file)
	if err != nil {
		return Host{}, err
	}
	arch, err := Architecture(runtime.GOARCH)
	if err != nil {
		return Host{}, err
	}
	memory, err := memoryTotal()
	if err != nil {
		return Host{}, err
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs("/", &disk); err != nil {
		return Host{}, err
	}
	free := disk.Bavail * uint64(disk.Bsize)
	if memory < minimumMemory {
		return Host{}, fmt.Errorf("INSUFFICIENT_MEMORY: have %d need %d", memory, minimumMemory)
	}
	if free < minimumDisk {
		return Host{}, fmt.Errorf("INSUFFICIENT_DISK: have %d need %d", free, minimumDisk)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return Host{}, err
	}
	return Host{Hostname: hostname, OS: id, OSVersion: osVersion, Architecture: arch, MemoryBytes: memory, DiskBytes: free, Capabilities: []string{"systemd"}, Installer: version, Nonce: nonce}, nil
}

func memoryTotal() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			return kib * 1024, err
		}
	}
	return 0, errors.New("MemTotal not found")
}
