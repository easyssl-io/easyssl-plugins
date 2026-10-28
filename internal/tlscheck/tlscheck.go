// Package tlscheck asks a TLS server which certificate it presents, to check
// after a reload that a server serves the Certificate just written.
//
// A reload command returning says little. `apachectl -k graceful`, `nginx -s
// reload` and `systemctl reload` return once the signal is sent; the server
// loads the configuration afterwards, and when that fails Apache exits and
// nginx keeps serving what it loaded before, both after the command has
// returned 0.
package tlscheck

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

// Endpoint is one place a client reaches a certificate: an address, a port,
// the server name it sends, and the key type it asks for when the server holds
// one certificate per type ("RSA" or "ECDSA", empty for any).
type Endpoint struct {
	IP, Port, SNI, Alg string
}

// String reads "ADDR:PORT sni=NAME", plus "key=ALG" when the client asks for
// a key type.
func (e Endpoint) String() string {
	ip, sni := e.IP, e.SNI
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	if sni == "" {
		sni = "(none)"
	}
	out := ip + ":" + e.Port + " sni=" + sni
	if e.Alg != "" {
		out += " key=" + e.Alg
	}
	return out
}

const (
	// Window is how long Verify waits for every place to serve the new
	// Certificate: a graceful reload replaces workers as their connections
	// end.
	Window      = 10 * time.Second
	every       = time.Second
	dialTimeout = 3 * time.Second
)

// ErrGone is a server that exited while Verify waited.
var ErrGone = errors.New("the master exited")

// Verify waits until every endpoint serves leaf, alive reporting the server
// still running, and writes what each served to stdout. The string is the
// run's last line on success.
func Verify(alive func() bool, eps []Endpoint, leaf []byte, stdout io.Writer) (string, error) {
	if len(eps) == 0 {
		return "Installed and reloaded. No place to check what is served was found.", nil
	}
	want := Fingerprint(leaf)
	got := map[string]string{}
	deadline := time.Now().Add(Window)
	for {
		if !alive() {
			return "", ErrGone
		}
		pending := 0
		for _, e := range eps {
			k := e.String()
			if got[k] == want {
				continue
			}
			got[k] = Served(e)
			if got[k] != want {
				pending++
			}
		}
		if pending == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(every)
	}
	if !alive() {
		return "", ErrGone
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
		return "", fmt.Errorf("after %s, %d of %d places still did not serve the new Certificate: %s", Window, len(bad), len(eps), strings.Join(bad, ", "))
	}
	return fmt.Sprintf("Installed, reloaded, and served at all %d places checked.", len(eps)), nil
}

// Fingerprint names a certificate by the SHA-256 of its DER.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256 " + hex.EncodeToString(sum[:])
}

// Served connects to e and names the leaf it presents, or why it could not.
// Validity is not checked: the question is which certificate is served, not
// whether a client would trust it.
func Served(e Endpoint) string {
	// #nosec G402 -- not trust: the leaf is compared with the one just written,
	// by fingerprint, and a self-signed or expired one must still be named.
	conf := &tls.Config{InsecureSkipVerify: true}
	if e.SNI != "" && net.ParseIP(e.SNI) == nil {
		conf.ServerName = e.SNI
	}
	// With TLS 1.2 the cipher suite decides which of a server's certificates
	// it sends, so offering only one key type's suites asks for that one.
	switch e.Alg {
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
	c, err := d.Dial("tcp", net.JoinHostPort(e.IP, e.Port))
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
	return Fingerprint(certs[0].Raw)
}
