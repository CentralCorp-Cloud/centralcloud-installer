package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/cli"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/config"
	cclogging "github.com/CentralCorp-Cloud/centralcloud-installer/internal/logging"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/release"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

var (
	version          = "dev"
	commit           = "unknown"
	buildDate        = "unknown"
	releasePublicKey = release.DefaultPublicKey
	traefikImage     = "traefik:v3.4.4@sha256:9b0e9d788816d722703eae57ebf8b4d52ad98e02b76f0362d5a040ef46902ef7"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	correlationID := newCorrelationID()
	log := cclogging.New(os.Stderr, cfg.Verbose).With("correlation_id", correlationID)
	app := cli.App{
		Version: version, Commit: commit, BuildDate: buildDate, Config: cfg,
		Runner: runner.OS{DryRun: cfg.DryRun, Record: func(command string) { log.Debug("command", "argv", command) }},
		HTTP:   &http.Client{Timeout: cfg.HTTPTimeout}, Log: log,
		Output:       func(format string, values ...any) { fmt.Printf(format+"\n", values...) },
		TraefikImage: traefikImage, ReleasePublicKey: releasePublicKey,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	if err := app.Run(ctx); err != nil {
		log.Error("installation interrupted", "error", err)
		fmt.Fprintf(os.Stderr, "\nInstallation interrompue\nMessage : %s\nCorrelation ID : %s\n", cclogging.Redact(err.Error()), correlationID)
		os.Exit(1)
	}
}

func newCorrelationID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
