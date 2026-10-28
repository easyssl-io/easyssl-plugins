package ops

import (
	"syscall"
	"testing"
)

// The version probe executes the binary it finds running, which anyone can
// name `apache`, so it runs as whoever runs that process: as the user for a
// user's process, and as this Plugin only for root's own.
func TestTheVersionProbeRunsAsTheProcessOwner(t *testing.T) {
	defer func(f func(*syscall.Credential, string) string) { probe = f }(probe)
	var as *syscall.Credential
	probe = func(c *syscall.Credential, exe string) string {
		as = c
		return "Server version: Apache/2.4.66 (Unix)\n"
	}

	user := cred{UID: 1000, GID: 1000, Groups: []uint32{1000}}
	if !isApache("/home/u/bin/apache-probe", user, map[string]string{}) {
		t.Fatal("a binary answering as Apache was not taken for one")
	}
	if as == nil || as.Uid != 1000 || as.Gid != 1000 {
		t.Fatalf("a user's process was probed as %+v, want uid and gid 1000", as)
	}

	as = &syscall.Credential{}
	isApache("/usr/sbin/apache2", cred{}, map[string]string{})
	if as != nil {
		t.Fatalf("root's process was probed with %+v, want this process's own credentials", as)
	}
}

// A process whose ids cannot be read is not given root's by default.
func TestCredOfAProcessGoneIsUnknown(t *testing.T) {
	if _, ok := credOf(1 << 30); ok {
		t.Fatal("the credentials of a process that does not exist read as known")
	}
}
