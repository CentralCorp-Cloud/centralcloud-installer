package main

import (
	"regexp"
	"testing"
)

func TestCorrelationIDIsUUID(t *testing.T) {
	value := newCorrelationID()
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value) {
		t.Fatalf("invalid correlation ID: %s", value)
	}
}

func TestTraefikImageIsPinnedToSupportedRelease(t *testing.T) {
	const expected = "traefik:v3.7.8@sha256:4299bbed850421258fc5448c2e0e6ad350981d4d335a68de11b92448aedbefe5"

	if traefikImage != expected {
		t.Fatalf("traefikImage = %q, want %q", traefikImage, expected)
	}
}
