// Package testkeys makes keys and self-signed certificates for the tests of
// this module's packages.
package testkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Key is a new key: RSA 2048 for "rsa", ECDSA P-256 for anything else.
func Key(t testing.TB, alg string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	if alg == "rsa" {
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Cert is a self-signed certificate for name, as PEM.
func Cert(t testing.TB, key crypto.Signer, name string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// PEM is a key as PKCS #8 PEM.
func PEM(t testing.TB, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
