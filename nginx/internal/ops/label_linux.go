package ops

import (
	"errors"
	"syscall"
)

// copyLabel gives dst the SELinux label src has. A file created in a directory
// takes that directory's default label, which is usually right; copying is
// what keeps a file an administrator labeled by hand readable by nginx under
// an enforcing policy. A filesystem or kernel without the attribute has
// nothing to copy.
func copyLabel(src, dst string) error {
	const attr = "security.selinux"
	buf := make([]byte, 256)
	n, err := syscall.Getxattr(src, attr, buf)
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return syscall.Setxattr(dst, attr, buf[:n], 0)
}
