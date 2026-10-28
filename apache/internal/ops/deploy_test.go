package ops

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deployAheadTo runs Deploy with no Apache running, as for a Target set up
// before the configuration that uses it, with commands that record their
// order in dir/log and a test command exiting testExit.
func deployAheadTo(t *testing.T, dir, cert, key, certPath, keyPath string, testExit int) (string, error) {
	t.Helper()
	defer func(f func() ([]*master, error)) { scanMasters = f }(scanMasters)
	scanMasters = func() ([]*master, error) { return nil, nil }
	log := filepath.Join(dir, "log")
	req := DeployRequest{
		CertificatePem: cert, PrivateKeyPem: key,
		Settings: map[string]string{
			SettingCertificate: certPath, SettingKey: keyPath,
			SettingTest:   "echo test >> " + log + "; exit " + string(rune('0'+testExit)),
			SettingReload: "echo reload >> " + log,
		},
	}
	var out bytes.Buffer
	err := Deploy(context.Background(), req, &out, &out)
	return out.String(), err
}

func newPair(t *testing.T, name string) (string, string) {
	t.Helper()
	k := newKey(t, "ec")
	der := selfSigned(t, k, name)
	return string(der), string(pemKey(t, k))
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A Target ahead of its configuration gets its directories created, and the
// test and the reload run in that order.
func TestDeployAheadCreatesDirectories(t *testing.T) {
	dir := ownedDir(t)
	cert, key := newPair(t, "ahead.test")
	cp, kp := filepath.Join(dir, "new", "a.crt"), filepath.Join(dir, "new", "a.key")
	out, err := deployAheadTo(t, dir, cert, key, cp, kp, 0)
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	if read(t, cp) != cert || read(t, kp) != key {
		t.Fatal("the files were not written")
	}
	if got := read(t, filepath.Join(dir, "log")); got != "test\nreload\n" {
		t.Fatalf("commands ran as %q", got)
	}
}

// A failing test puts the previous files back and does not reload.
func TestDeployAheadFailedTestRestores(t *testing.T) {
	dir := ownedDir(t)
	cp, kp := filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")
	oldCert, oldKey := newPair(t, "old.test")
	if err := os.WriteFile(cp, []byte(oldCert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(oldKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, key := newPair(t, "new.test")
	out, err := deployAheadTo(t, dir, cert, key, cp, kp, 1)
	if err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("deploy = %v\n%s", err, out)
	}
	if read(t, cp) != oldCert || read(t, kp) != oldKey {
		t.Fatal("the previous files were not put back")
	}
	if got := read(t, filepath.Join(dir, "log")); got != "test\n" {
		t.Fatalf("commands ran as %q", got)
	}
}

// What deploy refuses before writing anything: a pair that does not belong
// together, an encrypted key, and a path another ACME client manages.
func TestDeployRefusals(t *testing.T) {
	dir := ownedDir(t)
	a, _ := newPair(t, "a.test")
	_, bKey := newPair(t, "b.test")
	if _, err := deployAheadTo(t, dir, a, bKey, filepath.Join(dir, "x.crt"), filepath.Join(dir, "x.key"), 0); err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Errorf("a mismatched pair: %v", err)
	}
	cert, key := newPair(t, "c.test")
	enc := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	kp := filepath.Join(dir, "enc.key")
	if err := os.WriteFile(kp, []byte(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := deployAheadTo(t, dir, cert, key, filepath.Join(dir, "enc.crt"), kp, 0); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("an encrypted current key: %v", err)
	}
	if read(t, kp) != enc {
		t.Error("the encrypted key changed")
	}
	le := filepath.Join(dir, "etc", "letsencrypt", "live", "x")
	if _, err := deployAheadTo(t, dir, cert, key, filepath.Join(le, "fullchain.pem"), filepath.Join(le, "privkey.pem"), 0); err == nil || !strings.Contains(err.Error(), "another ACME client") {
		t.Errorf("a certbot path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "log")); !os.IsNotExist(err) {
		t.Error("a command ran for a refused Deployment")
	}
}

// ownedDir is a fresh directory only its owner can write, as
// hostfile.WriterFor requires of every directory on the way to a file.
func ownedDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func pemKey(t *testing.T, k crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
