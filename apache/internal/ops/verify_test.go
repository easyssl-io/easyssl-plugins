package ops

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func pemKey(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func tlsPair(t *testing.T, alg, name string) (tls.Certificate, []byte) {
	t.Helper()
	k := newKey(t, alg)
	c := selfSigned(t, k, name)
	pair, err := tls.X509KeyPair(c, pemKey(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return pair, pair.Certificate[0]
}

// TestServedPicksKeyType checks that an endpoint asking for a key type gets
// that one from a server holding both, as a dual RSA and ECDSA virtual host
// does.
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
		if got := served(endpoint{ip: "127.0.0.1", port: port, sni: "dual.test", alg: alg}); got != fingerprint(der) {
			t.Errorf("asking for %s: got %s, want %s", alg, got, fingerprint(der))
		}
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
	if got := served(endpoint{ip: "127.0.0.1", port: port}); got != "plain HTTP, not TLS" {
		t.Errorf("got %q", got)
	}
}
