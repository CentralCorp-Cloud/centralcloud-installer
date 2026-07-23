package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Material struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
}

func Generate(nodeID, fqdn string) (Material, error) {
	if nodeID == "" || fqdn == "" || strings.ContainsAny(fqdn, " /") {
		return Material{}, errors.New("node ID and valid FQDN are required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	return materialFromKey(key, nodeID, fqdn)
}

func GenerateFromPrivateKey(nodeID, fqdn string, privateKeyPEM []byte) (Material, error) {
	block, trailing := pem.Decode(privateKeyPEM)
	if block == nil || len(trailing) != 0 || block.Type != "PRIVATE KEY" {
		return Material{}, errors.New("invalid existing node private key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Material{}, fmt.Errorf("parse existing node private key: %w", err)
	}
	key, ok := value.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return Material{}, errors.New("existing node private key must be ECDSA P-256")
	}
	return materialFromKey(key, nodeID, fqdn)
}

func materialFromKey(key *ecdsa.PrivateKey, nodeID, fqdn string) (Material, error) {
	if nodeID == "" || fqdn == "" || strings.ContainsAny(fqdn, " /") {
		return Material{}, errors.New("node ID and valid FQDN are required")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	uri, err := parseSPIFFE("spiffe://centralcloud/node/" + nodeID)
	if err != nil {
		return Material{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: fqdn},
		DNSNames: []string{fqdn},
		URIs:     aliasURLs([]*urlAlias{uri}),
	}, key)
	if err != nil {
		return Material{}, err
	}
	return Material{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

func ValidateCertificate(certificatePEM, chainPEM, privateKeyPEM []byte, fqdn string, now time.Time) error {
	certBlock, _ := pem.Decode(certificatePEM)
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if certBlock == nil || keyBlock == nil {
		return errors.New("CERTIFICATE_INVALID: invalid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	keyValue, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	key, keyOK := keyValue.(*ecdsa.PrivateKey)
	publicKey, publicOK := cert.PublicKey.(*ecdsa.PublicKey)
	if !keyOK || !publicOK || !publicKey.Equal(&key.PublicKey) {
		return errors.New("CERTIFICATE_INVALID: public key mismatch")
	}
	if err := cert.VerifyHostname(fqdn); err != nil {
		return fmt.Errorf("CERTIFICATE_INVALID: %w", err)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("CERTIFICATE_INVALID: certificate is not currently valid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(chainPEM) {
		return errors.New("CERTIFICATE_INVALID: empty chain")
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: fqdn, Roots: roots, CurrentTime: now})
	if err != nil {
		return fmt.Errorf("CERTIFICATE_INVALID: %w", err)
	}
	return nil
}

func Install(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".tls-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
