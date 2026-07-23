package detection

import (
	"strings"
	"testing"
)

func TestParseSupportedOS(t *testing.T) {
	for _, value := range []string{"ID=debian\nVERSION_ID=12\n", "ID=debian\nVERSION_ID=\"13\"\n", "ID=ubuntu\nVERSION_ID=22.04\n", "ID=ubuntu\nVERSION_ID=\"24.04\"\n"} {
		if _, _, err := ParseOSRelease(strings.NewReader(value)); err != nil {
			t.Fatalf("expected supported OS: %v", err)
		}
	}
}

func TestRejectUnsupportedOSAndArchitecture(t *testing.T) {
	if _, _, err := ParseOSRelease(strings.NewReader("ID=centos\nVERSION_ID=9\n")); err == nil {
		t.Fatal("expected unsupported OS")
	}
	if _, err := Architecture("386"); err == nil {
		t.Fatal("expected unsupported architecture")
	}
}
