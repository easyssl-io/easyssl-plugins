package ops

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Checking what Apache serves after the reload. The reload command returning
// says little: `-k graceful` and `systemctl reload` return once the signal is
// sent, the master loads the configuration afterwards, and when that fails it
// exits while the command has already returned 0. So every place discovery
// found the file served is asked over TLS which certificate it now presents.

const (
	verifyFor   = 10 * time.Second // a graceful reload replaces children as their connections end
	verifyEvery = time.Second
	dialTimeout = 3 * time.Second
)

// endpointsFor lists where the file is served, once each. An endpoint that
// asks for a key type (a virtual host with one certificate per type) asks for
// the new Certificate's, which deploy's key-type guard has made the one this
// file now holds.
func endpointsFor(f *certFile, alg string) []endpoint {
	var out []endpoint
	seen := map[string]bool{}
	for _, l := range f.locs {
		for _, e := range l.endpoints {
			if e.alg != "" {
				e.alg = alg
			}
			if k := e.String(); !seen[k] {
				seen[k] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// verify waits until every endpoint serves the leaf, the master staying alive,
// and says what each served.
func verify(m *master, eps []endpoint, leaf []byte, stdout io.Writer) (string, error) {
	if len(eps) == 0 {
		return "Installed and reloaded. No place to check what is served was found.", nil
	}
	want := fingerprint(leaf)
	got := map[string]string{}
	deadline := time.Now().Add(verifyFor)
	for {
		if !m.alive() {
			return "", errMasterGone
		}
		pending := 0
		for _, e := range eps {
			k := e.String()
			if got[k] == want {
				continue
			}
			got[k] = served(e)
			if got[k] != want {
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(verifyEvery)
	}
	if !m.alive() {
		return "", errMasterGone
	}
	var bad []string
	for _, e := range eps {
		k := e.String()
		if got[k] == want {
			fmt.Fprintf(stdout, "serves the new Certificate: %s\n", k)
		} else {
			fmt.Fprintf(stdout, "does not serve the new Certificate: %s (%s)\n", k, got[k])
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		return "", fmt.Errorf("after %s, %d of %d places still did not serve the new Certificate: %s", verifyFor, len(bad), len(eps), strings.Join(bad, ", "))
	}
	return fmt.Sprintf("Installed, reloaded, and served at all %d places checked.", len(eps)), nil
}

// errMasterGone is a master that exited after the reload began.
var errMasterGone = errors.New("the master exited")

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256 " + hex.EncodeToString(sum[:])
}

// served connects to e and names the leaf it presents, or why it could not.
// Validity is not checked: the question is which certificate is served, not
// whether a client would trust it.
func served(e endpoint) string {
	// #nosec G402 -- not trust: the leaf is compared with the one just written,
	// by fingerprint, and a self-signed or expired one must still be named.
	conf := &tls.Config{InsecureSkipVerify: true}
	if isHostname(e.sni) {
		conf.ServerName = e.sni
	}
	// With TLS 1.2 the cipher suite decides which of a server's certificates
	// it sends, so offering only one key type's suites asks for that one.
	switch e.alg {
	case "RSA":
		conf.MaxVersion = tls.VersionTLS12
		conf.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		}
	case "ECDSA":
		conf.MaxVersion = tls.VersionTLS12
		conf.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		}
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: conf}
	c, err := d.Dial("tcp", net.JoinHostPort(e.ip, e.port))
	if err != nil {
		var re tls.RecordHeaderError
		if errors.As(err, &re) && bytes.HasPrefix(re.RecordHeader[:], []byte("HTTP")) {
			return "plain HTTP, not TLS"
		}
		return err.Error()
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "no certificate"
	}
	return fingerprint(certs[0].Raw)
}
