package ops

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deployTo runs Deploy with the Target's files under dir and commands that
// record their order in dir/log, and the test command exiting testExit.
func deployTo(t *testing.T, dir string, m material, chain string, testExit int, certPath, keyPath string) (string, error) {
	t.Helper()
	log := filepath.Join(dir, "log")
	req := DeployRequest{
		CertificatePem: m.cert,
		ChainPem:       chain,
		PrivateKeyPem:  m.key,
		Settings: map[string]string{
			SettingCertificate: certPath,
			SettingKey:         keyPath,
			SettingTest:        "echo test >> " + log + "; exit " + string(rune('0'+testExit)),
			SettingReload:      "echo reload >> " + log,
		},
	}
	var out, errOut bytes.Buffer
	err := Deploy(context.Background(), req, &out, &errOut)
	return out.String() + errOut.String(), err
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func content(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDeployCopiesPermissionsTestsThenReloads(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "site.crt"), filepath.Join(dir, "site.key")
	if err := os.WriteFile(cert, []byte("old cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("old key"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := issue(t, "ec", "site.example.test")
	chain := issue(t, "ec", "issuer.example.test").cert
	out, err := deployTo(t, dir, m, chain, 0, cert, key)
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	if got := content(t, cert); got != m.cert+chain {
		t.Fatalf("certificate file is not the certificate followed by the chain:\n%s", got)
	}
	if content(t, key) != m.key {
		t.Fatal("key file is not the key")
	}
	if mode(t, cert) != 0o644 || mode(t, key) != 0o640 {
		t.Fatalf("modes %04o and %04o, want the replaced files' 0644 and 0640", mode(t, cert), mode(t, key))
	}
	if content(t, filepath.Join(dir, "log")) != "test\nreload\n" {
		t.Fatalf("commands ran as %q, want test then reload", content(t, filepath.Join(dir, "log")))
	}
	if !strings.HasSuffix(strings.TrimSpace(out), liveNote) {
		t.Fatalf("output does not end with the note that a reload is not confirmation:\n%s", out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Fatalf("a temporary file was left behind: %v", entries)
	}
}

func TestDeployNewFilesAre0600(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "new", "site.crt"), filepath.Join(dir, "new", "site.key")
	if out, err := deployTo(t, dir, issue(t, "ec", "a.example.test"), "", 0, cert, key); err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	if mode(t, cert) != 0o600 || mode(t, key) != 0o600 {
		t.Fatalf("modes %04o and %04o, want 0600 for files with nothing to copy from", mode(t, cert), mode(t, key))
	}
}

func TestFailedTestPutsTheFilesBackAndDoesNotReload(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "site.crt"), filepath.Join(dir, "site.key")
	if err := os.WriteFile(cert, []byte("old cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := deployTo(t, dir, issue(t, "ec", "a.example.test"), "", 1, cert, key)
	if err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("deploy = %v, want a failure saying the files were put back\n%s", err, out)
	}
	if content(t, cert) != "old cert" || content(t, key) != "old key" {
		t.Fatal("the previous files were not restored")
	}
	if content(t, filepath.Join(dir, "log")) != "test\n" {
		t.Fatalf("commands ran as %q, want the test alone", content(t, filepath.Join(dir, "log")))
	}
}

func TestFailedTestRemovesFilesThatDidNotExist(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "site.crt"), filepath.Join(dir, "site.key")
	if _, err := deployTo(t, dir, issue(t, "ec", "a.example.test"), "", 1, cert, key); err == nil {
		t.Fatal("deploy succeeded with a failing test")
	}
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived a failed test although it did not exist before", p)
		}
	}
}

func TestDeployWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "archive", "cert1.pem")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "live.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	m := issue(t, "ec", "a.example.test")
	if out, err := deployTo(t, dir, m, "", 0, link, filepath.Join(dir, "key.pem")); err != nil {
		t.Fatalf("deploy: %v\n%s", err, out)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a regular file")
	}
	if content(t, real) != m.cert {
		t.Fatal("the file behind the symlink was not written")
	}
}

func TestDeployRefusesBadSettings(t *testing.T) {
	dir := t.TempDir()
	m := issue(t, "ec", "a.example.test")
	if _, err := deployTo(t, dir, m, "", 0, "relative.crt", filepath.Join(dir, "k")); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path: %v", err)
	}
	same := filepath.Join(dir, "both.pem")
	if _, err := deployTo(t, dir, m, "", 0, same, same); err == nil {
		t.Fatal("one file for both the certificate and the key was accepted")
	}
	var out bytes.Buffer
	if err := Deploy(context.Background(), DeployRequest{Settings: map[string]string{}}, &out, &out); err == nil {
		t.Fatal("empty settings were accepted")
	}
}

// The dual guard: replacing the RSA half of an RSA and ECDSA pair with an
// ECDSA Certificate is refused, the same algorithm is fine, and so is a path
// no running nginx loads.
func TestDualGuard(t *testing.T) {
	rsaM, ecM := issue(t, "rsa", "dual.example.test"), issue(t, "ec", "dual.example.test")
	root := tree(t, map[string]string{"rsa.crt": rsaM.cert, "ec.crt": ecM.cert})
	b := block{file: root + "/site.conf", certs: []ref{{resolved: root + "/rsa.crt"}, {resolved: root + "/ec.crt"}}}
	serving := func(string) []block { return []block{b} }

	err := checkDual(root+"/rsa.crt", x509.ECDSA, serving)
	if err == nil || !strings.Contains(err.Error(), "Request an RSA Certificate") {
		t.Fatalf("ECDSA onto the RSA half: %v", err)
	}
	if err := checkDual(root+"/rsa.crt", x509.RSA, serving); err != nil {
		t.Fatalf("RSA onto the RSA half: %v", err)
	}
	if err := checkDual(root+"/elsewhere.crt", x509.ECDSA, func(string) []block { return nil }); err != nil {
		t.Fatalf("a path nginx does not load yet: %v", err)
	}
	single := block{file: root + "/one.conf", certs: []ref{{resolved: root + "/rsa.crt"}}}
	if err := checkDual(root+"/rsa.crt", x509.ECDSA, func(string) []block { return []block{single} }); err != nil {
		t.Fatalf("switching a single-certificate block's algorithm: %v", err)
	}
}

// The pairing guard: a Target whose key file is not the one the configuration
// pairs its certificate with is refused, naming the file and line to set.
func TestPairingGuard(t *testing.T) {
	m := issue(t, "ec", "a.example.test")
	root := tree(t, map[string]string{"site.crt": m.cert, "site.key": m.key})
	b := block{file: root + "/site.conf",
		certs: []ref{{line: 3, resolved: root + "/site.crt"}},
		keys:  []ref{{line: 4, resolved: root + "/site.key"}}}
	err := checkPairing(root+"/site.crt", root+"/elsewhere.key", []block{b})
	if err == nil || !strings.Contains(err.Error(), "site.conf:4") || !strings.Contains(err.Error(), "Set ssl_certificate_key to "+root+"/site.key") {
		t.Fatalf("a key file nginx does not pair: %v", err)
	}
	if err := checkPairing(root+"/site.crt", root+"/site.key", []block{b}); err != nil {
		t.Fatalf("the paired key file: %v", err)
	}
	if err := checkPairing(root+"/new.crt", root+"/new.key", nil); err != nil {
		t.Fatalf("a path no nginx loads: %v", err)
	}
}
