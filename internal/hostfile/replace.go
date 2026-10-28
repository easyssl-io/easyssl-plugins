// Package hostfile replaces a server's certificate and key files on the host
// so that only their content changes, as the user a file's directory belongs
// to, and reports what keeps a path from being replaced safely.
//
// A file is replaced by writing a temporary file beside it and renaming it over
// the old one, so a reader sees either file whole and never part of one. The
// rename creates a new inode, which carries nothing of the old file's metadata,
// so the temporary file is given the old file's owner, group and mode and every
// extended attribute (POSIX ACLs are the system.posix_acl_access attribute,
// the SELinux label is security.selinux), loses whatever it inherited that
// the old file lacks (a directory's default ACL), and is compared with the old
// file before the rename. A file the rename cannot replace faithfully is
// refused: one with more than one hard link, whose other names would keep the
// old content, and an immutable or append-only one.
package hostfile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// DefaultMode is a new file's mode, when there is no file to copy one from.
// A certificate file is public, but the stricter mode costs nothing, since a
// server reads both files as root, and one rule is easier to trust.
const DefaultMode os.FileMode = 0o600

// dirMode is a directory Replace creates for a file that has none yet: a
// Target set up before the configuration that uses it.
const dirMode os.FileMode = 0o700

// Meta is everything about a file except its content that a replacement
// keeps.
type Meta struct {
	Mode   os.FileMode
	UID    uint32
	GID    uint32
	Nlink  uint64
	Xattrs map[string][]byte
}

// MetaOf reads a file's Meta without following a symlink.
func MetaOf(path string) (Meta, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Meta{}, err
	}
	m := Meta{Mode: info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		m.UID, m.GID, m.Nlink = st.Uid, st.Gid, uint64(st.Nlink)
	}
	if m.Xattrs, err = xattrs(path); err != nil {
		return Meta{}, err
	}
	return m, nil
}

// Differs names what makes two files' metadata differ, "" when nothing does.
func (a Meta) Differs(b Meta) string {
	if a.Mode != b.Mode {
		return fmt.Sprintf("mode %04o instead of %04o", uint32(b.Mode.Perm()), uint32(a.Mode.Perm()))
	}
	if a.UID != b.UID || a.GID != b.GID {
		return fmt.Sprintf("owner %d:%d instead of %d:%d", b.UID, b.GID, a.UID, a.GID)
	}
	var names []string
	for k := range a.Xattrs {
		names = append(names, k)
	}
	for k := range b.Xattrs {
		if _, ok := a.Xattrs[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		if !bytes.Equal(a.Xattrs[k], b.Xattrs[k]) {
			return fmt.Sprintf("extended attribute %s differs", k)
		}
	}
	return ""
}

// Replace puts data at path so that only the content changes, as described
// above. A path with no file yet gets a new file at DefaultMode, and the
// directories it lacks at 0700.
func Replace(path string, data []byte) error {
	old, err := MetaOf(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existed {
		if err := Replaceable(path, old); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	if !existed {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".easyssl-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, DefaultMode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // a no-op once the rename has succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if existed {
		if err := clone(tmp, old); err != nil {
			return fmt.Errorf("giving the new %s the old one's metadata: %w", path, err)
		}
		got, err := MetaOf(tmp)
		if err != nil {
			return err
		}
		if d := old.Differs(got); d != "" {
			return fmt.Errorf("the new %s would have %s, so it was not replaced", path, d)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// clone gives the file at tmp the metadata old describes. The extended
// attributes go first: setting system.posix_acl_access rewrites the group
// mode bits, so the mode is set last.
func clone(tmp string, old Meta) error {
	cur, err := MetaOf(tmp)
	if err != nil {
		return err
	}
	if cur.UID != old.UID || cur.GID != old.GID {
		uid := int(old.UID)
		if os.Geteuid() != 0 {
			uid = -1 // only the group can change without root, and only to one of ours
		}
		if err := os.Lchown(tmp, uid, int(old.GID)); err != nil {
			return err
		}
	}
	for k, v := range old.Xattrs {
		if err := setXattr(tmp, k, v); err != nil {
			return fmt.Errorf("extended attribute %s: %w", k, err)
		}
	}
	for k := range cur.Xattrs {
		if _, ok := old.Xattrs[k]; !ok {
			if err := removeXattr(tmp, k); err != nil {
				return fmt.Errorf("extended attribute %s the old file lacks: %w", k, err)
			}
		}
	}
	return os.Chmod(tmp, old.Mode)
}

// Replaceable refuses a file a rename cannot replace faithfully.
func Replaceable(path string, m Meta) error {
	if m.Nlink > 1 {
		return fmt.Errorf("%s has %d hard links, and replacing it would leave the other names with the previous content", path, m.Nlink)
	}
	if Immutable(path) {
		return fmt.Errorf("%s is immutable or append-only (chattr +i or +a), so it cannot be replaced", path)
	}
	return nil
}

// Describe words how a file just written relates to the one it replaced, for
// a Deployment's output.
func Describe(path string, replaced bool) string {
	m, err := MetaOf(path)
	if err != nil {
		return "?"
	}
	how := "everything but the content kept from the file it replaced"
	if !replaced {
		how = "a new file"
	}
	return fmt.Sprintf("mode %04o, owner %d:%d, %s", uint32(m.Mode.Perm()), m.UID, m.GID, how)
}
