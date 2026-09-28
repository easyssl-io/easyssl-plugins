package ops

import (
	"os/exec"
	"strings"
	"testing"
)

// A path from a running nginx reaches a root shell as one word, whatever it
// holds: shell syntax in it is data, not commands.
func TestShellQuoteKeepsAPathOneWord(t *testing.T) {
	for _, path := range []string{
		"/usr/sbin/nginx",
		"/opt/my nginx/sbin/nginx",
		"/tmp/x; touch /tmp/pwned",
		"/tmp/$(id)`id`",
		"/tmp/it's",
	} {
		// printf prints its single argument between markers; a word the
		// shell split or executed would show as more, or as something else.
		out, err := exec.Command("/bin/sh", "-e", "-c", "printf '[%s]' "+shellQuote(path)).Output()
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if got := string(out); got != "["+path+"]" {
			t.Fatalf("%q reached the shell as %s", path, got)
		}
	}
	if got := shellQuote("/usr/sbin/nginx"); strings.Contains(got, "'") {
		t.Fatalf("a plain path was quoted: %s", got)
	}
}
