package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateCSRContainsExactIdentity(t *testing.T) {
	material, err := Generate("123e4567-e89b-42d3-a456-426614174000", "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material.CSRPEM)
	if block == nil {
		t.Fatal("missing CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("invalid CSR: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "node.example.com" || len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://centralcloud/node/123e4567-e89b-42d3-a456-426614174000" {
		t.Fatalf("unexpected SANs: %#v %#v", csr.DNSNames, csr.URIs)
	}
	if len(material.PrivateKeyPEM) == 0 {
		t.Fatal("private key missing")
	}

	reused, err := GenerateFromPrivateKey("123e4567-e89b-42d3-a456-426614174000", "node.example.com", material.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	originalKey, _ := pem.Decode(material.PrivateKeyPEM)
	reusedKey, _ := pem.Decode(reused.PrivateKeyPEM)
	if !bytes.Equal(originalKey.Bytes, reusedKey.Bytes) {
		t.Fatal("private key identity changed")
	}
}
