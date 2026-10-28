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
	"crypto/x509"
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
	unchecked := map[string]bool{}
	deadline := time.Now().Add(Window)
	for {
		if !alive() {
			return "", ErrGone
		}
		pending := 0
		for _, e := range eps {
			k := e.String()
			if got[k] == want || unchecked[k] {
				continue
			}
			r := served(e)
			got[k], unchecked[k] = r.text, r.unchecked
			if got[k] != want && !r.unchecked {
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
	var bad, skipped []string
	for _, e := range eps {
		k := e.String()
		switch {
		case got[k] == want:
			fmt.Fprintf(stdout, "serves the new Certificate: %s\n", k)
		case unchecked[k]:
			fmt.Fprintf(stdout, "could not be checked: %s (%s)\n", k, got[k])
			skipped = append(skipped, k)
		default:
			fmt.Fprintf(stdout, "does not serve the new Certificate: %s (%s)\n", k, got[k])
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		return "", fmt.Errorf("after %s, %d of %d places still did not serve the new Certificate: %s", Window, len(bad), len(eps), strings.Join(bad, ", "))
	}
	if len(skipped) > 0 {
		return fmt.Sprintf("Installed, reloaded, and served at all %d places checked; %d more could not be checked for their key type: %s.",
			len(eps)-len(skipped), len(skipped), strings.Join(skipped, ", ")), nil
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
func Served(e Endpoint) string { return served(e).text }

// result is a leaf's fingerprint, or why there is none. unchecked is a server
// that answered with a certificate of the other key type when one cannot be
// asked for, which says nothing about the one this endpoint expects.
type result struct {
	text      string
	unchecked bool
}

func served(e Endpoint) result {
	leaf, err := handshake(e, e.Alg)
	if e.Alg != "" && refusesTLS12(err) {
		// The type is asked for through TLS 1.2's cipher suites. In TLS 1.3 the
		// signature algorithms the client offers decide, and Go's client offers
		// all of them, so a server accepting only TLS 1.3 sends whichever
		// certificate it prefers.
		leaf, err = handshake(e, "")
		if err == nil && leaf.PublicKeyAlgorithm.String() != e.Alg {
			return result{fmt.Sprintf("the server accepts only TLS 1.3, where a client cannot ask for one key type, and sent its %s certificate",
				leaf.PublicKeyAlgorithm), true}
		}
	}
	if err != nil {
		var re tls.RecordHeaderError
		if errors.As(err, &re) && bytes.HasPrefix(re.RecordHeader[:], []byte("HTTP")) {
			return result{text: "plain HTTP, not TLS"}
		}
		return result{text: err.Error()}
	}
	return result{text: Fingerprint(leaf.Raw)}
}

// refusesTLS12 is a server ending the handshake with a protocol_version alert,
// because the highest version offered, TLS 1.2, is too old for it. Go returns
// an alert the server sent as a "remote error" carrying the alert's text; its
// AlertError type is for QUIC alone.
func refusesTLS12(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error" && op.Err.Error() == "tls: protocol version not supported"
}

// handshake connects to e, asking for alg's certificate when alg is set, and
// returns the leaf presented.
func handshake(e Endpoint, alg string) (*x509.Certificate, error) {
	// #nosec G402 -- not trust: the leaf is compared with the one just written,
	// by fingerprint, and a self-signed or expired one must still be named.
	conf := &tls.Config{InsecureSkipVerify: true}
	if e.SNI != "" && net.ParseIP(e.SNI) == nil {
		conf.ServerName = e.SNI
	}
	// With TLS 1.2 the cipher suite decides which of a server's certificates
	// it sends, so offering only one key type's suites asks for that one.
	switch alg {
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
		return nil, err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs[0], nil
}
