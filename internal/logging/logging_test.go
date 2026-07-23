package logging

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	input := `Authorization: Bearer abc token="secret-value" password=hunter2`
	output := Redact(input)
	for _, secret := range []string{"abc", "secret-value", "hunter2"} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret leaked: %s", output)
		}
	}
}
