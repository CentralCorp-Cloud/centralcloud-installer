package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultAPIURL = "https://cloud.centralcloud.fr"

type Config struct {
	Command         string
	APIURL          string
	Channel         string
	TokenFile       string
	NonInteractive  bool
	DeleteTokenFile bool
	SkipFirewall    bool
	DryRun          bool
	Verbose         bool
	ConfigFile      string
	StateDir        string
	ManifestURL     string
	PublicKey       string
	MinimumMemory   uint64
	MinimumDisk     uint64
	HTTPTimeout     time.Duration
}

type fileConfig struct {
	APIURL          *string `yaml:"api_url"`
	Channel         *string `yaml:"channel"`
	TokenFile       *string `yaml:"token_file"`
	NonInteractive  *bool   `yaml:"non_interactive"`
	DeleteTokenFile *bool   `yaml:"delete_token_file"`
	SkipFirewall    *bool   `yaml:"skip_firewall"`
	DryRun          *bool   `yaml:"dry_run"`
	Verbose         *bool   `yaml:"verbose"`
	StateDir        *string `yaml:"state_dir"`
	ManifestURL     *string `yaml:"manifest_url"`
	PublicKey       *string `yaml:"release_public_key"`
	MinimumMemory   *uint64 `yaml:"minimum_memory_bytes"`
	MinimumDisk     *uint64 `yaml:"minimum_disk_bytes"`
	HTTPTimeout     *string `yaml:"http_timeout"`
}

func Parse(args []string) (Config, error) {
	var c Config
	if len(args) == 0 {
		return c, errors.New("a command is required")
	}
	c.Command = args[0]
	switch c.Command {
	case "install", "status", "doctor", "repair", "update", "version", "uninstall":
	default:
		return c, fmt.Errorf("unknown command %q", c.Command)
	}
	fs := flag.NewFlagSet(c.Command, flag.ContinueOnError)
	fs.StringVar(&c.APIURL, "api-url", DefaultAPIURL, "Dashboard API URL")
	fs.StringVar(&c.Channel, "channel", "stable", "Agent release channel")
	fs.StringVar(&c.TokenFile, "token-file", "", "one-time enrollment token file")
	fs.BoolVar(&c.NonInteractive, "non-interactive", false, "disable prompts")
	fs.BoolVar(&c.DeleteTokenFile, "delete-token-file", false, "remove token file after exchange")
	fs.BoolVar(&c.SkipFirewall, "skip-firewall", false, "do not change firewall rules")
	fs.BoolVar(&c.DryRun, "dry-run", false, "show actions without changing the host")
	fs.BoolVar(&c.Verbose, "verbose", false, "enable verbose logs")
	fs.StringVar(&c.ConfigFile, "config", "/etc/centralcloud-installer/config.yaml", "installer configuration")
	fs.StringVar(&c.StateDir, "state-dir", "/var/lib/centralcloud-installer", "installer state directory")
	fs.StringVar(&c.ManifestURL, "manifest-url", "", "exact signed Agent manifest URL")
	fs.StringVar(&c.PublicKey, "release-public-key", "", "base64 Ed25519 public key")
	fs.Uint64Var(&c.MinimumMemory, "minimum-memory-bytes", 2<<30, "minimum RAM")
	fs.Uint64Var(&c.MinimumDisk, "minimum-disk-bytes", 20<<30, "minimum free disk")
	fs.DurationVar(&c.HTTPTimeout, "http-timeout", 30*time.Second, "HTTP request timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return c, err
	}
	explicit := map[string]bool{}
	fs.Visit(func(value *flag.Flag) {
		explicit[value.Name] = true
	})
	if err := applyConfigFile(&c, explicit); err != nil {
		return c, err
	}
	if c.Channel != "stable" && c.Channel != "beta" {
		return c, errors.New("channel must be stable or beta")
	}
	if c.APIURL == "" || c.StateDir == "" {
		return c, errors.New("api-url and state-dir are required")
	}
	apiURL, err := url.Parse(c.APIURL)
	if err != nil || apiURL.Scheme != "https" || apiURL.Host == "" || apiURL.User != nil {
		return c, errors.New("api-url must be an HTTPS URL without user information")
	}
	if !filepath.IsAbs(c.StateDir) {
		return c, errors.New("state-dir must be absolute")
	}
	return c, nil
}

func applyConfigFile(c *Config, explicit map[string]bool) error {
	info, err := os.Lstat(c.ConfigFile)
	if errors.Is(err, os.ErrNotExist) && !explicit["config"] {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect config file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("config file must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("config file must not be writable by group or others")
	}
	data, err := os.ReadFile(c.ConfigFile) // #nosec G304 -- explicit CLI configuration path.
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("config file exceeds 64 KiB")
	}
	var values fileConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&values); err != nil {
		return fmt.Errorf("decode config file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("config file must contain exactly one YAML document")
		}
		return fmt.Errorf("decode trailing config data: %w", err)
	}
	setString := func(flagName string, value *string, target *string) {
		if !explicit[flagName] && value != nil {
			*target = *value
		}
	}
	setBool := func(flagName string, value *bool, target *bool) {
		if !explicit[flagName] && value != nil {
			*target = *value
		}
	}
	setUint64 := func(flagName string, value *uint64, target *uint64) {
		if !explicit[flagName] && value != nil {
			*target = *value
		}
	}
	setString("api-url", values.APIURL, &c.APIURL)
	setString("channel", values.Channel, &c.Channel)
	setString("token-file", values.TokenFile, &c.TokenFile)
	setBool("non-interactive", values.NonInteractive, &c.NonInteractive)
	setBool("delete-token-file", values.DeleteTokenFile, &c.DeleteTokenFile)
	setBool("skip-firewall", values.SkipFirewall, &c.SkipFirewall)
	setBool("dry-run", values.DryRun, &c.DryRun)
	setBool("verbose", values.Verbose, &c.Verbose)
	setString("state-dir", values.StateDir, &c.StateDir)
	setString("manifest-url", values.ManifestURL, &c.ManifestURL)
	setString("release-public-key", values.PublicKey, &c.PublicKey)
	setUint64("minimum-memory-bytes", values.MinimumMemory, &c.MinimumMemory)
	setUint64("minimum-disk-bytes", values.MinimumDisk, &c.MinimumDisk)
	if !explicit["http-timeout"] && values.HTTPTimeout != nil {
		duration, err := time.ParseDuration(*values.HTTPTimeout)
		if err != nil {
			return fmt.Errorf("invalid config http_timeout: %w", err)
		}
		c.HTTPTimeout = duration
	}
	return nil
}

func EnrollmentToken(c Config) ([]byte, func(), error) {
	path := c.TokenFile
	if path == "" {
		if value, ok := os.LookupEnv("CENTRALCLOUD_ENROLLMENT_TOKEN"); ok {
			_ = os.Unsetenv("CENTRALCLOUD_ENROLLMENT_TOKEN")
			if len(value) < 32 {
				return nil, func() {}, errors.New("enrollment token is too short")
			}
			return []byte(value), func() {}, nil
		}
	}
	if path == "" {
		return nil, func() {}, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("inspect token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, func() {}, errors.New("token file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, func() {}, errors.New("token file must not be accessible by group or others")
	}
	if ownerUID(info) != 0 && os.Geteuid() == 0 {
		return nil, func() {}, errors.New("token file must be owned by root")
	}
	value, err := os.ReadFile(path) // #nosec G304 -- explicit CLI secret path.
	if err != nil {
		return nil, func() {}, err
	}
	if len(value) < 32 || len(value) > 4096 {
		return nil, func() {}, errors.New("invalid enrollment token length")
	}
	cleanup := func() {}
	if c.DeleteTokenFile {
		cleanup = func() { _ = os.Remove(path) }
	}
	return value, cleanup, nil
}
