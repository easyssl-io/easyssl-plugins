//go:build !linux

package hostfile

// The Plugin runs on Linux; these let it build and its tests run elsewhere,
// where files are taken to have no extended attributes and no flags.

func xattrs(string) (map[string][]byte, error) { return map[string][]byte{}, nil }

func setXattr(string, string, []byte) error { return nil }

func removeXattr(string, string) error { return nil }

func Immutable(string) bool { return false }
