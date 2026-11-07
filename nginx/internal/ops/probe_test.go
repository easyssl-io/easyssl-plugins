package ops

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testroot"
)

// Discovery runs the binary of every process titled "nginx: master process",
// which anyone can start from a binary of their own, so -V runs as whoever runs
// that process, and as this Plugin only for root's own.
func TestTheVersionProbeRunsAsTheMastersUser(t *testing.T) {
	defer func(f func(*syscall.Credential, string) string) { versionOf = f }(versionOf)
	var as *syscall.Credential
	versionOf = func(c *syscall.Credential, exe string) string {
		as = c
		return "configure arguments: --prefix=/opt/nginx\n"
	}

	user := &syscall.Credential{Uid: 1000, Gid: 1000, Groups: []uint32{1000}}
	if b := buildOf("/home/u/bin/nginx", user); b.prefix != "/opt/nginx" {
		t.Fatalf("prefix %q, want /opt/nginx", b.prefix)
	}
	if as != user {
		t.Fatalf("a user's master was probed as %+v, want %+v", as, user)
	}

	in := instance{Exe: "/home/u/bin/nginx", Cred: user}
	as = nil
	startFrom(&in, "nginx: master process /home/u/bin/nginx")
	if as != user {
		t.Fatalf("startFrom probed a user's master as %+v, want %+v", as, user)
	}
}

// A process whose ids cannot be read is not given root's by default: the scan
// skips it instead of running its binary.
func TestCredOfAProcessGoneIsUnknown(t *testing.T) {
	if c, ok := credOf(1 << 30); ok {
		t.Fatalf("the credentials of a process that does not exist read as known: %+v", c)
	}
}

// The probe really drops to the master's user: a binary that reports the uid
// it runs as, in place of a prefix, reports nobody's.
func TestTheVersionProbeDropsToTheMastersUser(t *testing.T) {
	testroot.Require(t)
	dir, err := os.MkdirTemp("", "nginx-probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "nginx")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho \"configure arguments: --prefix=/uid-$(id -u)\" >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	nobody := &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}
	if got := buildOf(exe, nobody).prefix; got != "/uid-65534" {
		t.Fatalf("the probe ran with prefix %q, want /uid-65534", got)
	}
	if got := buildOf(exe, nil).prefix; got != "/uid-0" {
		t.Fatalf("root's own master was probed with prefix %q, want /uid-0", got)
	}
}
