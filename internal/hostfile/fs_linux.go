package hostfile

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// xattrs reads every extended attribute of a file this process may read.
// A filesystem without extended attributes has none.
func xattrs(path string) (map[string][]byte, error) {
	out := map[string][]byte{}
	n, err := syscall.Listxattr(path, nil)
	if errors.Is(err, syscall.ENOTSUP) {
		return out, nil
	}
	if err != nil || n == 0 {
		return out, err
	}
	buf := make([]byte, n)
	if n, err = syscall.Listxattr(path, buf); err != nil {
		return nil, err
	}
	for _, name := range bytes.Split(buf[:n], []byte{0}) {
		if len(name) == 0 {
			continue
		}
		k := string(name)
		size, err := syscall.Getxattr(path, k, nil)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return nil, err
		}
		v := make([]byte, size)
		if size, err = syscall.Getxattr(path, k, v); err != nil {
			return nil, err
		}
		out[k] = v[:size]
	}
	return out, nil
}

func setXattr(path, name string, v []byte) error {
	return syscall.Setxattr(path, name, v, 0)
}

func removeXattr(path, name string) error {
	return syscall.Removexattr(path, name)
}

// FS_IOC_GETFLAGS and the two flags that keep a file from being replaced, from
// linux/fs.h.
const (
	fsIocGetflags = 0x80086601
	fsImmutableFl = 0x00000010
	fsAppendFl    = 0x00000020
)

// Immutable reports a file chattr made immutable or append-only, which a
// rename cannot replace.
func Immutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var flags int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags, uintptr(unsafe.Pointer(&flags))); e != 0 {
		return false
	}
	return flags&(fsImmutableFl|fsAppendFl) != 0
}
