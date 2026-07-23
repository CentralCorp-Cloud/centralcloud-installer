package validation

import (
	"context"
	"errors"
	"testing"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func TestRunChecksEveryRequiredService(t *testing.T) {
	executor := &runner.Fake{}
	checks, err := Run(context.Background(), executor)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 6 || len(executor.Calls) != 6 {
		t.Fatalf("incomplete validation: checks=%#v calls=%#v", checks, executor.Calls)
	}
	for _, check := range checks {
		if check.Status != "ok" {
			t.Fatalf("unexpected validation result: %#v", checks)
		}
	}
}

func TestRunStopsAtFirstFailedCheck(t *testing.T) {
	executor := &runner.Fake{Errors: map[string]error{"pg_isready": errors.New("offline")}}
	checks, err := Run(context.Background(), executor)
	if err == nil {
		t.Fatal("expected validation failure")
	}
	if checks[len(checks)-1].Name != "postgresql" || checks[len(checks)-1].Status != "error" {
		t.Fatalf("unexpected failed validation: %#v", checks)
	}
}

func TestRunFinalCreatesAndRemovesAnEphemeralDockerNetwork(t *testing.T) {
	executor := &runner.Fake{}
	checks, err := RunFinal(context.Background(), executor)
	if err != nil {
		t.Fatal(err)
	}
	if checks[len(checks)-1] != (Check{Name: "docker-network", Status: "ok"}) {
		t.Fatalf("network validation is missing: %#v", checks)
	}
	var creates, removes int
	for _, call := range executor.Calls {
		if len(call) >= 3 && call[0] == "docker" && call[1] == "network" {
			switch call[2] {
			case "create":
				creates++
			case "rm":
				removes++
			}
		}
	}
	if creates != 1 || removes != 2 {
		t.Fatalf("unexpected network lifecycle: %#v", executor.Calls)
	}
}
