package ops

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"

	"github.com/easyssl-io/easyssl-contract/wire"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Reading certificates and keys from files, for discovery and for the checks
// deploy makes before writing and reloading.

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
	der, err := pemfile.LeafDER(b)
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
	ci.sans, ci.sanErr = pemfile.GeneralNames(ci.leaf)
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
