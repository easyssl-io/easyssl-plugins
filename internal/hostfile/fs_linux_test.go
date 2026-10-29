package hostfile

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testroot"
)

// acl encodes a POSIX ACL as the kernel stores it in system.posix_acl_*,
// granting nobody (65534) read beside the owner's read and write.
func acl() []byte {
	const undefined = 0xffffffff
	b := binary.LittleEndian.AppendUint32(nil, 2) // version
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{
		{0x01, 6, undefined}, // owner
		{0x02, 4, 65534},     // named user
		{0x04, 0, undefined}, // owning group
		{0x10, 4, undefined}, // mask
		{0x20, 0, undefined}, // others
	} {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// setOrSkip sets an extended attribute, skipping the test where the
// filesystem refuses that kind.
func setOrSkip(t *testing.T, path, name string, v []byte) {
	t.Helper()
	if err := syscall.Setxattr(path, name, v, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EPERM) {
			testroot.Unavailable(t, "the filesystem of %s refuses %s: %v", path, name, err)
		}
		t.Fatal(err)
	}
}

// A replacement keeps the ACL and the user.* attribute the old file had,
// which a rename alone would drop.
func TestReplaceKeepsACLAndUserAttributes(t *testing.T) {
	p := filepath.Join(ownedDir(t), "k.pem")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOrSkip(t, p, "system.posix_acl_access", acl())
	setOrSkip(t, p, "user.mark", []byte("keep"))
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
	for _, k := range []string{"system.posix_acl_access", "user.mark"} {
		if _, ok := after.Xattrs[k]; !ok {
			t.Errorf("%s was lost", k)
		}
	}
}

// A directory's default ACL gives the temporary file an ACL the old file
// never had, and the replacement must not keep it.
func TestReplaceDropsAnACLTheOldFileLacked(t *testing.T) {
	d := ownedDir(t)
	p := filepath.Join(d, "k.pem")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOrSkip(t, d, "system.posix_acl_default", acl())
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
	if _, ok := after.Xattrs["system.posix_acl_access"]; ok {
		t.Error("the file kept the ACL its directory's default gave the temporary file")
	}
	if d := before.Differs(after); d != "" {
		t.Errorf("metadata changed: %s", d)
	}
}
