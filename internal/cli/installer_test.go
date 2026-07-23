package cli

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/config"
	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func TestAgentTokenIsReducedToAStableDigest(t *testing.T) {
	token := strings.Repeat("s", 48)
	first, err := agentTokenSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	second, err := agentTokenSHA256(token)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 || strings.Contains(first, token) {
		t.Fatalf("unexpected token digest %q", first)
	}
	if _, err := agentTokenSHA256("short"); err == nil {
		t.Fatal("short Agent token accepted")
	}
}

func TestUninstallOnlyStopsAgentAndPreservesData(t *testing.T) {
	executor := &runner.Fake{}
	app := App{
		Config: config.Config{Command: "uninstall"},
		Runner: executor,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Output: func(string, ...any) {},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.Calls) != 2 {
		t.Fatalf("unexpected uninstall calls: %#v", executor.Calls)
	}
	for _, call := range executor.Calls {
		joined := strings.Join(call, " ")
		for _, destructive := range []string{"rm", "docker volume", "dropdb", "postgres"} {
			if strings.Contains(joined, destructive) {
				t.Fatalf("destructive uninstall command: %s", joined)
			}
		}
	}
}
