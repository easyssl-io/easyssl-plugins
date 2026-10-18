package ops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ownedDir is a fresh directory only its owner can write, as writerFor
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

func TestReplaceFileKeepsMetadata(t *testing.T) {
	p := filepath.Join(ownedDir(t), "k.pem")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil { // past the umask
		t.Fatal(err)
	}
	before, err := metaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	after, err := metaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if d := before.differs(after); d != "" {
		t.Errorf("metadata changed: %s", d)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content = %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".k.pem.easyssl-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestReplaceFileNewFile(t *testing.T) {
	p := filepath.Join(ownedDir(t), "new.pem")
	if err := replaceFile(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	m, err := metaOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.mode.Perm() != defaultMode {
		t.Errorf("mode = %04o, want %04o", m.mode.Perm(), defaultMode)
	}
}

func TestReplaceFileRefusesHardLinks(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "c.pem")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(d, "other.pem")); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(p, []byte("new")); err == nil {
		t.Fatal("a hard-linked file was replaced")
	}
	if len(pathProblems(p)) == 0 {
		t.Error("discovery reports nothing about a hard-linked file")
	}
}

func TestWriterFor(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "c.pem")
	w, err := writerFor(p)
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
	if _, err := writerFor(filepath.Join(open, "c.pem")); !errors.Is(err, errUnsafe) {
		t.Errorf("a world-writable directory: err = %v, want errUnsafe", err)
	}

	// A sticky directory on the way is fine, and is not as the file's own.
	sticky := filepath.Join(d, "sticky")
	inner := filepath.Join(sticky, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := writerFor(filepath.Join(inner, "c.pem")); err != nil {
		t.Errorf("a sticky directory on the way: %v", err)
	}
	if _, err := writerFor(filepath.Join(sticky, "c.pem")); !errors.Is(err, errUnsafe) {
		t.Errorf("a sticky directory holding the file: err = %v, want errUnsafe", err)
	}
}

func TestPathProblemsACME(t *testing.T) {
	if len(pathProblems("/etc/letsencrypt/archive/x/cert1.pem")) == 0 {
		t.Error("a certbot path is not reported")
	}
}

func TestWritePairAndRestore(t *testing.T) {
	d := ownedDir(t)
	cp, kp := filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	oldKey := newKey(t, "ec")
	if err := os.WriteFile(cp, selfSigned(t, oldKey, "old.test"), 0o644); err != nil {
		t.Fatal(err)
	}
	newK := newKey(t, "ec")
	cert := selfSigned(t, newK, "new.test")
	key := pemKey(t, newK)
	w, err := writePair(cp, kp, cert, key, &discard{}, &discard{})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cp); string(b) != string(cert) {
		t.Error("the certificate was not written")
	}
	w.restore(&discard{}, &discard{})
	if b, _ := os.ReadFile(cp); string(b) == string(cert) {
		t.Error("the certificate was not put back")
	}
	if _, err := os.Stat(kp); !os.IsNotExist(err) {
		t.Error("a key file that did not exist before was left behind")
	}

	// A pair that does not belong together is caught after the write and
	// undone.
	if _, err := writePair(cp, kp, cert, pemKey(t, oldKey), &discard{}, &discard{}); err == nil {
		t.Error("a mismatched pair was accepted")
	}
	if b, _ := os.ReadFile(cp); string(b) == string(cert) {
		t.Error("a refused pair was left in place")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
