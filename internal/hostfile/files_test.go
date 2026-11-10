package hostfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteAllKeepsModeAndReverts(t *testing.T) {
	d := ownedDir(t)
	a, b := filepath.Join(d, "a.conf"), filepath.Join(d, "b.conf")
	if err := os.WriteFile(a, []byte("a old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b old"), 0o600); err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(a, then, then); err != nil {
		t.Fatal(err)
	}
	w, err := WriteAll("--write-file", []Change{{a, []byte("a old"), []byte("a new")}, {b, []byte("b old"), []byte("b new")}})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{a: "a new", b: "b new"} {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("%s holds %q, want %q", p, got, want)
		}
	}
	if fi, _ := os.Stat(a); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %04o, want the replaced file's 0640", fi.Mode().Perm())
	}
	if err := w.Revert(); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{a: "a old", b: "b old"} {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("after Revert %s holds %q, want %q", p, got, want)
		}
	}
	if fi, _ := os.Stat(a); !fi.ModTime().Equal(then) {
		t.Errorf("after Revert a.conf was modified at %v, want its own %v back", fi.ModTime(), then)
	}
	if entries, _ := os.ReadDir(d); len(entries) != 2 {
		t.Errorf("a temporary file was left behind: %v", entries)
	}
}

// A file edited since it was read is refused, and what was already written
// is put back.
func TestWriteAllRefusesAFileChangedSinceItWasRead(t *testing.T) {
	d := ownedDir(t)
	a, b := filepath.Join(d, "a.conf"), filepath.Join(d, "b.conf")
	if err := os.WriteFile(a, []byte("a old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := WriteAll("--write-file", []Change{{a, []byte("a old"), []byte("a new")}, {b, []byte("b old"), []byte("b new")}})
	if err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("WriteAll = %v, want a refusal", err)
	}
	if got, _ := os.ReadFile(a); string(got) != "a old" {
		t.Errorf("a.conf holds %q, want it put back", got)
	}
	if got, _ := os.ReadFile(b); string(got) != "b edited" {
		t.Errorf("b.conf holds %q, want it untouched", got)
	}
	if _, err := WriteAll("--write-file", []Change{{filepath.Join(d, "missing"), []byte("x"), []byte("y")}}); err == nil {
		t.Error("a file that does not exist was written")
	}
}
