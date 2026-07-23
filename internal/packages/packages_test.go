package packages

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CentralCorp-Cloud/centralcloud-installer/internal/runner"
)

func TestInstallReturnsRedactedCommandDiagnostic(t *testing.T) {
	fake := &runner.Fake{
		Results: map[string][]byte{
			"apt-get": []byte("E: dépôt non signé\npassword=should-not-leak\n"),
		},
		Errors: map[string]error{
			"apt-get": errors.New("exit status 100"),
		},
	}

	err := Install(context.Background(), fake)
	if err == nil {
		t.Fatal("Install() error = nil, want failure")
	}
	message := err.Error()
	for _, expected := range []string{
		"PACKAGES_COMMAND_FAILED",
		"apt-get update",
		"E: dépôt non signé",
		"password=[REDACTED]",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("Install() error = %q, want %q", message, expected)
		}
	}
	if strings.Contains(message, "should-not-leak") {
		t.Fatalf("Install() leaked a secret: %q", message)
	}
}

func TestSafeDiagnosticRemovesControlCharactersAndTruncates(t *testing.T) {
	diagnostic := safeDiagnostic([]byte("\x00" + strings.Repeat("a", 5000)))

	if strings.ContainsRune(diagnostic, '\x00') {
		t.Fatalf("safeDiagnostic() retained a control character")
	}
	if !strings.HasPrefix(diagnostic, "[sortie tronquée]\n") {
		t.Fatalf("safeDiagnostic() = %q, want truncation marker", diagnostic[:32])
	}
	if len([]rune(diagnostic)) > 4096+32 {
		t.Fatalf("safeDiagnostic() was not bounded")
	}
}
