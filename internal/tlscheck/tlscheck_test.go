package tlscheck

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testkeys"
)

func tlsPair(t *testing.T, alg, name string) (tls.Certificate, []byte) {
	t.Helper()
	k := testkeys.Key(t, alg)
	pair, err := tls.X509KeyPair(testkeys.Cert(t, k, name), testkeys.PEM(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return pair, pair.Certificate[0]
}

// TestServedPicksKeyType checks that an endpoint asking for a key type gets
// that one from a server holding both, as a dual RSA and ECDSA server does.
func TestServedPicksKeyType(t *testing.T) {
	rsaPair, rsaDER := tlsPair(t, "rsa", "dual.test")
	ecPair, ecDER := tlsPair(t, "ec", "dual.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ecPair, rsaPair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for alg, der := range map[string][]byte{"RSA": rsaDER, "ECDSA": ecDER} {
		if got := Served(Endpoint{IP: "127.0.0.1", Port: port, SNI: "dual.test", Alg: alg}); got != Fingerprint(der) {
			t.Errorf("asking for %s: got %s, want %s", alg, got, Fingerprint(der))
		}
	}
	var out discard
	if _, err := Verify(func() bool { return true }, []Endpoint{{IP: "127.0.0.1", Port: port, SNI: "dual.test", Alg: "ECDSA"}}, ecDER, out); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// A dual server accepting only TLS 1.3 cannot be asked for one key type: the
// half it sends is checked as usual, and the other is reported as not
// checked rather than as not served, which would roll back a Certificate the
// server took. A wrong certificate of the expected type still fails.
func TestServedTLS13OnlyDualServer(t *testing.T) {
	rsaPair, rsaDER := tlsPair(t, "rsa", "dual.test")
	ecPair, ecDER := tlsPair(t, "ec", "dual.test")
	_, otherEC := tlsPair(t, "ec", "dual.test")
	// Go's server sends the first certificate the client's signature
	// algorithms allow, so with every one offered the ECDSA one goes out.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ecPair, rsaPair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ec := Endpoint{IP: "127.0.0.1", Port: port, SNI: "dual.test", Alg: "ECDSA"}
	rsa := Endpoint{IP: "127.0.0.1", Port: port, SNI: "dual.test", Alg: "RSA"}

	if got := Served(ec); got != Fingerprint(ecDER) {
		t.Errorf("the half the server sends: got %s, want %s", got, Fingerprint(ecDER))
	}
	if r := served(rsa); !r.unchecked {
		t.Errorf("the half it cannot be asked for: %+v, want unchecked", r)
	}
	alive := func() bool { return true }
	var out discard
	if line, err := Verify(alive, []Endpoint{ec, rsa}, ecDER, out); err != nil || !strings.Contains(line, "1 more could not be checked") {
		t.Errorf("Verify of the ECDSA half: %q, %v", line, err)
	}
	if _, err := Verify(alive, []Endpoint{rsa}, rsaDER, out); err != nil {
		t.Errorf("Verify of the RSA half, which cannot be checked, failed: %v", err)
	}
	if _, err := Verify(alive, []Endpoint{ec}, otherEC, out); err == nil {
		t.Error("Verify passed although the ECDSA half serves another certificate")
	}
}

func TestServedPlainHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		c.Close()
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if got := Served(Endpoint{IP: "127.0.0.1", Port: port}); got != "plain HTTP, not TLS" {
		t.Errorf("got %q", got)
	}
}

func TestVerifyGone(t *testing.T) {
	if _, err := Verify(func() bool { return false }, []Endpoint{{IP: "127.0.0.1", Port: "1"}}, nil, discard{}); err != ErrGone {
		t.Errorf("Verify with the server gone = %v, want ErrGone", err)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
