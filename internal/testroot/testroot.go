// Package testroot gates the tests that need Linux and root, so that the run
// meant to exercise them cannot pass by skipping them.
package testroot

import (
	"os"
	"runtime"
	"testing"
)

// Env is set by the run that executes the Plugins' tests as root. Under it, a
// test that cannot run as intended fails instead of skipping.
const Env = "EASYSSL_TEST_AS_ROOT"

// Require skips t unless it runs on Linux as root, or fails it under Env.
func Require(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return
	}
	Unavailable(t, "needs Linux and root")
}

// Unavailable skips t for something the host lacks, such as a filesystem
// feature, or fails it under Env, where the host is expected to have it.
func Unavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv(Env) != "" {
		t.Fatalf(format+" (required under "+Env+")", args...)
	}
	t.Skipf(format, args...)
}
