package ops

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-plugins/internal/testroot"
)

// The graceful command reads the master's whole configuration before it
// signals, so it runs as the user the master runs as; a supervisor's reload
// stays root's. This test process stands in for the master.
func TestAGracefulReloadRunsAsTheMastersUser(t *testing.T) {
	testroot.Require(t)
	self := os.Getpid()
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "httpd.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(self)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nobody := cred{UID: 65534, GID: 65534, Groups: []uint32{}}

	for _, c := range []struct {
		graceful bool
		want     string
	}{
		{true, "65534"},
		{false, "0"},
	} {
		m := &master{PID: self, Exe: exe, PidFile: pidFile, Cred: nobody, Graceful: c.graceful}
		var out bytes.Buffer
		if err := reload(context.Background(), m, "id -u", &out); err != nil {
			t.Fatalf("graceful=%v: %v\n%s", c.graceful, err, out.String())
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if got := lines[len(lines)-1]; got != c.want {
			t.Errorf("graceful=%v: the reload ran as uid %s, want %s", c.graceful, got, c.want)
		}
	}
}
