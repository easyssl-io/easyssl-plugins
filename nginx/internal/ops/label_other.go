//go:build !linux

package ops

// copyLabel is a no-op off Linux, where there is no SELinux label to keep.
// The Plugin only runs on Linux; this lets its tests run anywhere.
func copyLabel(src, dst string) error { return nil }
