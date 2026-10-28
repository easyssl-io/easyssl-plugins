package tlscheck

import (
	"crypto/tls"
	"net"
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
