package main

import "testing"

func TestTraefikImageIsPinnedToSupportedRelease(t *testing.T) {
	const expected = "traefik:v3.7.8@sha256:4299bbed850421258fc5448c2e0e6ad350981d4d335a68de11b92448aedbefe5"

	if traefikImage != expected {
		t.Fatalf("traefikImage = %q, want %q", traefikImage, expected)
	}
}
