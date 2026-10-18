package ops

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/easyssl-io/easyssl-contract/wire"
)

// Reading certificates and keys from files, for discovery and for the checks
// deploy makes before writing and reloading.

func pemBlocks(b []byte) []*pem.Block {
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

// errNoCertificate is a file with no certificate in it.
var errNoCertificate = errors.New("no PEM certificate")

// leafDER is the DER of the first certificate in a PEM file, unparsed, so a
// leaf crypto/x509 refuses (a negative serial) still has a fingerprint. The
// first is the leaf: SSLCertificateFile holds the leaf followed by its chain.
func leafDER(b []byte) ([]byte, error) {
	for _, blk := range pemBlocks(b) {
		if blk.Type == "CERTIFICATE" {
			return blk.Bytes, nil
		}
	}
	return nil, errNoCertificate
}

// certInfo is what discovery reports about a certificate file.
type certInfo struct {
	der      []byte
	leaf     *x509.Certificate // nil when crypto/x509 refuses the leaf
	parseErr error
	sha256   string
	sans     []string
	sanErr   error
	keyType  string
}

func readCert(path string) (certInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return certInfo{}, err
	}
	der, err := leafDER(b)
	if err != nil {
		return certInfo{}, err
	}
	sum := sha256.Sum256(der)
	ci := certInfo{der: der, sha256: hex.EncodeToString(sum[:])}
	ci.leaf, ci.parseErr = x509.ParseCertificate(der)
	if ci.parseErr != nil {
		ci.sanErr = ci.parseErr
		return ci, nil
	}
	ci.sans, ci.sanErr = generalNames(ci.leaf)
	ci.keyType = wire.KeyTypeOf(ci.leaf.PublicKey)
	return ci, nil
}

// alg names a certificate's key algorithm for grouping by key type, the way
// OpenSSL keeps one certificate per type in a context.
func (ci certInfo) alg() string {
	if ci.leaf == nil {
		return "?"
	}
	return ci.leaf.PublicKeyAlgorithm.String()
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

const (
	tagDNSName   = 2
	tagIPAddress = 7
)

// generalNames walks the subjectAltName extension in encoding order, which
// crypto/x509's DNSNames and IPAddresses lose by splitting names from
// addresses.
func generalNames(leaf *x509.Certificate) ([]string, error) {
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
				if l := len(v.Bytes); l == net.IPv4len || l == net.IPv6len {
					out = append(out, net.IP(v.Bytes).String())
				}
			}
		}
		return out, nil
	}
	return []string{}, nil
}

// encryptedKey reports a PEM private key protected by a passphrase: PKCS #8
// ("ENCRYPTED PRIVATE KEY") or the older OpenSSL form with a Proc-Type header.
func encryptedKey(b []byte) bool {
	for _, blk := range pemBlocks(b) {
		if blk.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			return true
		}
	}
	return false
}

// hasPrivateKey reports a private key among a file's PEM blocks.
func hasPrivateKey(b []byte) bool {
	for _, blk := range pemBlocks(b) {
		if strings.HasSuffix(blk.Type, "PRIVATE KEY") {
			return true
		}
	}
	return false
}

// parseKey reads the first unencrypted private key in PEM, in the three
// encodings mod_ssl accepts.
func parseKey(b []byte) (crypto.Signer, error) {
	for _, blk := range pemBlocks(b) {
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

// keyMatches reports whether a private key belongs to a certificate: the same
// check mod_ssl makes when it loads them, which `apachectl -t` does not make
// and whose failure makes the master exit on reload (AH02565).
func keyMatches(leaf *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	return ok && pub.Equal(leaf.PublicKey)
}

// pairMatches reads a certificate file and a key file, as mod_ssl would pair
// them, and reports whether they match. An encrypted key is not checked here:
// only the master, which already holds its passphrase, can read it.
func pairMatches(certPEM, keyPEM []byte) error {
	der, err := leafDER(certPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if encryptedKey(keyPEM) {
		return nil
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return err
	}
	if !keyMatches(leaf, key) {
		return errors.New("the private key does not match the certificate")
	}
	return nil
}
