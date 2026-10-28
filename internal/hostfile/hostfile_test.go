package hostfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testkeys"
)

// ownedDir is a fresh directory only its owner can write, as WriterFor
// requires of every directory on the way to a file.
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

func TestReplaceKeepsMetadata(t *testing.T) {
	p := filepath.Join(ownedDir(t), "k.pem")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil { // past the umask
		t.Fatal(err)
	}
	before, err := MetaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Replace(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	after, err := MetaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := before.Differs(after); d != "" {
		t.Errorf("metadata changed: %s", d)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content = %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".k.pem.easyssl-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// A new file is 0600, and the directories it lacks are created 0700, as for
// a Target set up before the configuration that uses it.
func TestReplaceNewFileAndDirectories(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "a", "b", "new.pem")
	if _, err := WriterFor(p); err != nil {
		t.Fatalf("a path whose directories do not exist yet: %v", err)
	}
	if err := Replace(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	m, err := MetaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode.Perm() != DefaultMode {
		t.Errorf("mode = %04o, want %04o", m.Mode.Perm(), DefaultMode)
	}
	fi, err := os.Stat(filepath.Join(d, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != dirMode {
		t.Errorf("directory mode = %04o, want %04o", fi.Mode().Perm(), dirMode)
	}
}

func TestReplaceRefusesHardLinks(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "c.pem")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(d, "other.pem")); err != nil {
		t.Fatal(err)
	}
	if err := Replace(p, []byte("new")); err == nil {
		t.Fatal("a hard-linked file was replaced")
	}
	if ps := Problems(p); len(ps) == 0 || ps[0].Kind != HardLink || ps[0].Links != 2 {
		t.Errorf("Problems = %+v, want one hard link problem", ps)
	}
}

func TestWriterFor(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "c.pem")
	w, err := WriterFor(p)
	if err != nil {
		t.Fatalf("an owner-only directory: %v", err)
	}
	if os.Geteuid() != 0 && (w == nil || w.UID != uint32(os.Geteuid())) {
		t.Errorf("writer = %+v, want this user", w)
	}

	open := filepath.Join(d, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := WriterFor(filepath.Join(open, "c.pem")); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a world-writable directory: err = %v, want ErrUnsafe", err)
	}

	// A sticky directory on the way is fine, and is not as the file's own,
	// nor when the directory below it does not exist yet, since others could
	// create it first.
	sticky := filepath.Join(d, "sticky")
	inner := filepath.Join(sticky, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := WriterFor(filepath.Join(inner, "c.pem")); err != nil {
		t.Errorf("a sticky directory on the way: %v", err)
	}
	if _, err := WriterFor(filepath.Join(sticky, "c.pem")); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a sticky directory holding the file: err = %v, want ErrUnsafe", err)
	}
	if _, err := WriterFor(filepath.Join(sticky, "missing", "c.pem")); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a sticky directory holding a missing directory: err = %v, want ErrUnsafe", err)
	}
}

func TestProblemsACME(t *testing.T) {
	ps := Problems("/etc/letsencrypt/archive/x/cert1.pem")
	if len(ps) == 0 || ps[0].Kind != ACMEManaged || ps[0].Dir != "etc/letsencrypt" {
		t.Errorf("Problems = %+v, want the certbot directory", ps)
	}
}

func TestWritePairAndRestore(t *testing.T) {
	d := ownedDir(t)
	cp, kp := filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	oldKey := testkeys.Key(t, "ec")
	if err := os.WriteFile(cp, testkeys.Cert(t, oldKey, "old.test"), 0o644); err != nil {
		t.Fatal(err)
	}
	newK := testkeys.Key(t, "ec")
	cert := testkeys.Cert(t, newK, "new.test")
	key := testkeys.PEM(t, newK)
	w, err := WritePair("write-file", cp, kp, cert, key, discard{}, discard{})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cp); string(b) != string(cert) {
		t.Error("the certificate was not written")
	}
	w.Restore(discard{}, discard{})
	if b, _ := os.ReadFile(cp); string(b) == string(cert) {
		t.Error("the certificate was not put back")
	}
	if _, err := os.Stat(kp); !os.IsNotExist(err) {
		t.Error("a key file that did not exist before was left behind")
	}

	// A pair that does not belong together is caught after the write and
	// undone.
	if _, err := WritePair("write-file", cp, kp, cert, testkeys.PEM(t, oldKey), discard{}, discard{}); err == nil {
		t.Error("a mismatched pair was accepted")
	}
	if b, _ := os.ReadFile(cp); string(b) == string(cert) {
		t.Error("a refused pair was left in place")
	}
}

func TestWritePairRefusesReplacingAnEncryptedKey(t *testing.T) {
	d := ownedDir(t)
	cp, kp := filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	enc := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	if err := os.WriteFile(kp, []byte(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	k := testkeys.Key(t, "ec")
	if _, err := WritePair("write-file", cp, kp, testkeys.Cert(t, k, "a.test"), testkeys.PEM(t, k), discard{}, discard{}); err == nil {
		t.Fatal("an encrypted key was replaced")
	}
	if b, _ := os.ReadFile(kp); string(b) != enc {
		t.Error("the encrypted key changed")
	}
	if _, err := os.Stat(cp); !os.IsNotExist(err) {
		t.Error("the certificate written before the refusal was left behind")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
