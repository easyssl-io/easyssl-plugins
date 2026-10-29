package hostfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/easyssl-io/easyssl-plugins/internal/testroot"
)

// nobody is the user these tests hand files and directories to.
const nobody = 65534

// FS_IOC_SETFLAGS, from linux/fs.h.
const fsIocSetflags = 0x40086602

// chflag turns one inode flag of a file on or off, as chattr does: the other
// flags are read and written back, because a filesystem refuses to clear some
// of its own, such as ext4's extents flag.
func chflag(path string, flag int32, on bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var flags int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags))); e != 0 {
		return e
	}
	if on {
		flags |= flag
	} else {
		flags &^= flag
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocSetflags, uintptr(unsafe.Pointer(&flags))); e != 0 {
		return e
	}
	return nil
}

// A file another user owns keeps that owner across a replace, which only root
// can give the new file.
func TestReplaceKeepsAnotherUsersOwnership(t *testing.T) {
	testroot.Require(t)
	p := filepath.Join(ownedDir(t), "k.pem")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, nobody, nobody); err != nil {
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
	if after.UID != nobody || after.GID != nobody {
		t.Errorf("owner = %d:%d, want %d:%d", after.UID, after.GID, nobody, nobody)
	}
	if d := before.Differs(after); d != "" {
		t.Errorf("metadata changed: %s", d)
	}
}

// An immutable or append-only file is reported at discovery and refused at
// deploy, its content untouched: a rename would replace it anyway, through
// the directory, and lose the flag.
func TestReplaceRefusesImmutableAndAppendOnlyFiles(t *testing.T) {
	testroot.Require(t)
	for _, c := range []struct {
		name string
		flag int32
	}{
		{"immutable", fsImmutableFl},
		{"append-only", fsAppendFl},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(ownedDir(t), "c.pem")
			if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := chflag(p, c.flag, true); err != nil {
				testroot.Unavailable(t, "cannot set inode flags on %s: %v", p, err)
			}
			t.Cleanup(func() {
				if err := chflag(p, c.flag, false); err != nil {
					t.Errorf("clearing the flag: %v", err)
				}
			})

			if ps := Problems(p); len(ps) != 1 || ps[0].Kind != ImmutableFile {
				t.Errorf("Problems = %+v, want one immutable file problem", ps)
			}
			if err := Replace(p, []byte("new")); err == nil {
				t.Fatal("the file was replaced")
			}
			if b, _ := os.ReadFile(p); string(b) != "old" {
				t.Errorf("content = %q, want the old one", b)
			}
		})
	}
}

// In a directory a user owns, that user writes, and a file there that belongs
// to someone else is refused: the user could not have given it that owner.
func TestWriterForAUsersDirectory(t *testing.T) {
	testroot.Require(t)
	d := filepath.Join(ownedDir(t), "user")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	w, err := WriterFor(filepath.Join(d, "c.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if w == nil || w.UID != nobody {
		t.Errorf("writer = %+v, want uid %d", w, nobody)
	}

	theirs := filepath.Join(d, "root.pem")
	if err := os.WriteFile(theirs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriterFor(theirs); !errors.Is(err, ErrUnsafe) {
		t.Errorf("a root-owned file in a user's directory: err = %v, want ErrUnsafe", err)
	}
}
