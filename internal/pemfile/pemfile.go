// Package pemfile reads the PEM certificates and private keys a TLS server
// loads, as OpenSSL would, for discovery and for the checks a Deployment makes
// before writing and reloading.
package pemfile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Blocks is every PEM block in b, in order.
func Blocks(b []byte) []*pem.Block {
	var out []*pem.Block
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		out = append(out, blk)
	}
	return out
}

// ErrNoCertificate is a file with no certificate in it, named apart from a
// parser's errors so a Plugin can word its warning in every language.
var ErrNoCertificate = errors.New("no PEM certificate")

// LeafDER is the DER of the first certificate in PEM, unparsed, so a leaf
// crypto/x509 refuses (a negative serial) still has a fingerprint. The first
// is the leaf: a server's certificate file holds the leaf followed by its
// chain.
func LeafDER(b []byte) ([]byte, error) {
	for _, blk := range Blocks(b) {
		if blk.Type == "CERTIFICATE" {
			return blk.Bytes, nil
		}
	}
	return nil, ErrNoCertificate
}

// ParseLeaf parses the first block of a Deployment's certificate PEM, which
// must be a certificate.
func ParseLeaf(certificatePEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the Deployment carries no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// JoinPEM is the certificate followed by its chain, each ending in one newline.
func JoinPEM(cert, chain string) string {
	out := strings.TrimRight(cert, "\n") + "\n"
	if c := strings.TrimSpace(chain); c != "" {
		out += c + "\n"
	}
	return out
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// GeneralName context-specific tags, RFC 5280 4.2.1.6.
const (
	tagDNSName   = 2
	tagIPAddress = 7
)

// GeneralNames walks the subjectAltName extension in encoding order, which
// crypto/x509's DNSNames and IPAddresses lose by splitting names from
// addresses: a SAN encoded DNS, IP, DNS would come back as two names and one
// address. Only dNSName and iPAddress are reported, the other choices not
// naming a TLS server. A certificate with no such extension has none.
func GeneralNames(leaf *x509.Certificate) ([]string, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			return nil, fmt.Errorf("subjectAltName: %w", err)
		}
		out := []string{}
		for rest := seq.Bytes; len(rest) > 0; {
			var v asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &v); err != nil {
				return nil, fmt.Errorf("subjectAltName entry: %w", err)
			}
			switch v.Tag {
			case tagDNSName:
				out = append(out, string(v.Bytes))
			case tagIPAddress:
				// Anything but 4 or 16 bytes is not an address, and is left out
				// rather than rendered as nonsense.
				if l := len(v.Bytes); l == net.IPv4len || l == net.IPv6len {
					out = append(out, net.IP(v.Bytes).String())
				}
			}
		}
		return out, nil
	}
	return []string{}, nil
}

// EncryptedKey reports a PEM private key protected by a passphrase: PKCS #8
// ("ENCRYPTED PRIVATE KEY") or the older OpenSSL form with a Proc-Type header.
func EncryptedKey(b []byte) bool {
	for _, blk := range Blocks(b) {
		if blk.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
	}
	return false
}

// HasPrivateKey reports a private key among b's PEM blocks.
func HasPrivateKey(b []byte) bool {
	for _, blk := range Blocks(b) {
		if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			return true
		}
	}
	return false
}

// ParseKey reads the first unencrypted private key in PEM, in the three
// encodings OpenSSL accepts: PKCS #8, PKCS #1 and SEC 1.
func ParseKey(b []byte) (crypto.Signer, error) {
	for _, blk := range Blocks(b) {
		if !strings.HasSuffix(blk.Type, "PRIVATE KEY") || blk.Type == "ENCRYPTED PRIVATE KEY" {
			continue
		}
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
		}
		if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("no private key this Plugin can read")
}

// KeyAlgorithm is the algorithm of the first private key in b, or
// UnknownPublicKeyAlgorithm when there is none it can read, an encrypted one
// included.
func KeyAlgorithm(b []byte) x509.PublicKeyAlgorithm {
	k, err := ParseKey(b)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	switch k.(type) {
	case *rsa.PrivateKey:
		return x509.RSA
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	case ed25519.PrivateKey:
		return x509.Ed25519
	}
	return x509.UnknownPublicKeyAlgorithm
}

// KeyMatches reports whether a private key belongs to a certificate, the check
// OpenSSL's SSL_CTX_check_private_key makes when a server loads the pair.
func KeyMatches(leaf *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	return ok && pub.Equal(leaf.PublicKey)
}

// PairMatches reads a certificate file's leaf and a key file and reports
// whether they belong together. An encrypted key is not checked: only the
// server, which holds its passphrase, can read it.
func PairMatches(certPEM, keyPEM []byte) error {
	der, err := LeafDER(certPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if EncryptedKey(keyPEM) {
		return nil
	}
	key, err := ParseKey(keyPEM)
	if err != nil {
		return err
	}
	if !KeyMatches(leaf, key) {
		return errors.New("the private key does not match the certificate")
	}
	return nil
}
