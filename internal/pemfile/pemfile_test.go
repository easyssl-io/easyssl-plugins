package pemfile

import (
	"crypto/x509"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testkeys"
)

func TestPairMatchesAndKeyAlgorithm(t *testing.T) {
	ec, rsa := testkeys.Key(t, "ec"), testkeys.Key(t, "rsa")
	cert := testkeys.Cert(t, ec, "a.test")
	if err := PairMatches(cert, testkeys.PEM(t, ec)); err != nil {
		t.Errorf("a matching pair: %v", err)
	}
	if err := PairMatches(cert, testkeys.PEM(t, rsa)); err == nil {
		t.Error("a mismatched pair was accepted")
	}
	if got := KeyAlgorithm(testkeys.PEM(t, rsa)); got != x509.RSA {
		t.Errorf("KeyAlgorithm = %v, want RSA", got)
	}
}

func TestEncryptedKey(t *testing.T) {
	for in, want := range map[string]bool{
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n":                                           true,
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n": true,
		"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n":                                                               false,
	} {
		if got := EncryptedKey([]byte(in)); got != want {
			t.Errorf("EncryptedKey(%q) = %v, want %v", in, got, want)
		}
		if want && KeyAlgorithm([]byte(in)) != x509.UnknownPublicKeyAlgorithm {
			t.Errorf("an encrypted key has a known algorithm: %q", in)
		}
	}
}

func TestLeafAndChain(t *testing.T) {
	k := testkeys.Key(t, "ec")
	leaf, i1, i2 := testkeys.Cert(t, k, "leaf.test"), testkeys.Cert(t, k, "i1.test"), testkeys.Cert(t, k, "i2.test")
	in := "text before\n" + string(leaf) + string(testkeys.PEM(t, k)) + string(i1) + "between\n" + string(i2)
	gotLeaf, gotChain := LeafAndChain([]byte(in))
	if gotLeaf != string(leaf) {
		t.Errorf("leaf %q, want the first certificate alone", gotLeaf)
	}
	if gotChain != string(i1)+string(i2) {
		t.Errorf("chain %q, want the two certificates after the leaf, without the key or the text", gotChain)
	}
	if l, c := LeafAndChain(testkeys.PEM(t, k)); l != "" || c != "" {
		t.Errorf("a file with no certificate gave %q, %q", l, c)
	}
	long := string(leaf)
	for range maxChain + 3 {
		long += string(i1)
	}
	if _, c := LeafAndChain([]byte(long)); len(Blocks([]byte(c))) != maxChain {
		t.Errorf("a long chain reported %d certificates, want %d", len(Blocks([]byte(c))), maxChain)
	}
}
