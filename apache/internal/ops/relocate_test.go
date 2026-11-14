package ops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// certbotHost is an Apache whose configuration names a certbot lineage three
// ways: an absolute path in double quotes, a key in single quotes, and a path
// relative to ServerRoot in a file an Include reaches through a symlink.
// Copies of the files are already where they are to move, as the Agent
// leaves them. The dump is what httpd would report for it.
func certbotHost(t *testing.T, changed ...string) (string, *master, configReader) {
	t.Helper()
	root := ownedDir(t)
	cert, key := newPair(t, "a.test")
	for p, c := range map[string]string{
		"httpd.conf": "Listen 9441\n<VirtualHost *:9441>\n  ServerName a.test\n" +
			"  SSLCertificateFile \"@ROOT@/le/live/a/fullchain.pem\"\n  SSLCertificateKeyFile '@ROOT@/le/live/a/privkey.pem'\n" +
			"</VirtualHost>\nInclude @ROOT@/sites/*.conf\n",
		"avail/a.conf": "Listen 9442\n<VirtualHost *:9442>\n  ServerName a.test\n" +
			"\tSSLCertificateFile le/live/a/fullchain.pem\n  SSLCertificateKeyFile @ROOT@/le/live/a/privkey.pem\n</VirtualHost>\n",
		"le/archive/a/cert1.pem":    cert,
		"le/archive/a/privkey1.pem": key,
		"easyssl/a/certificate.pem": cert,
		"easyssl/a/key.pem":         key,
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(strings.ReplaceAll(c, "@ROOT@", root)), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"sites/a.conf": "../avail/a.conf", "le/live/a/fullchain.pem": "../../archive/a/cert1.pem",
		"le/live/a/privkey.pem": "../../archive/a/privkey1.pem",
	} {
		full := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	m, read := caseOf(root, `# In file: @ROOT@/httpd.conf
#   1:
Listen 9441
#   2:
<VirtualHost *:9441>
  #   3:
  ServerName a.test
  #   4:
  SSLCertificateFile @ROOT@/le/live/a/fullchain.pem
  #   5:
  SSLCertificateKeyFile @ROOT@/le/live/a/privkey.pem
</VirtualHost>
# In file: @ROOT@/sites/a.conf
#   1:
Listen 9442
#   2:
<VirtualHost *:9442>
  #   3:
  ServerName a.test
  #   4:
  SSLCertificateFile le/live/a/fullchain.pem
  #   5:
  SSLCertificateKeyFile @ROOT@/le/live/a/privkey.pem
</VirtualHost>
`, "*:9441                 a.test (@ROOT@/httpd.conf:2)\n*:9442                 a.test (@ROOT@/sites/a.conf:2)\n")
	m.Graceful = false // a supervisor's reload, which needs no pid file guard
	if len(changed) > 0 {
		inner := read
		read = func(m *master) (*serverCfg, []string, error) {
			s, _, err := inner(m)
			return s, changed, err
		}
	}
	return root, m, read
}

// moveOut is the request the Agent sends: one move per spelling, and the
// references discovery reported.
func moveOut(t *testing.T, root string, m *master, read configReader) RelocateRequest {
	t.Helper()
	targets, _ := analyze([]*master{m}, read)
	if len(targets) != 1 {
		t.Fatalf("targets %+v", targets)
	}
	cert, key := root+"/easyssl/a/certificate.pem", root+"/easyssl/a/key.pem"
	return RelocateRequest{
		Moves: []plugincontract.Move{
			{From: root + "/le/live/a/fullchain.pem", To: cert},
			{From: "le/live/a/fullchain.pem", To: cert},
			{From: root + "/le/live/a/privkey.pem", To: key},
		},
		References: targets[0].References,
	}
}

// runRelocate runs relocate in English with the test, the reload and the
// check after it standing in for a running Apache, logging their order in
// root/log.
func runRelocate(t *testing.T, root string, req RelocateRequest, m *master, read configReader, testErr, confirm error) (string, error) {
	t.Helper()
	logTo := func(s string) {
		f, err := os.OpenFile(root+"/log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		io.WriteString(f, s+"\n")
	}
	defer func(a, b, c, d any) {
		testMaster = a.(func(context.Context, *master, io.Writer) error)
		reloadMaster = b.(func(context.Context, *master, io.Writer) error)
		confirmReload = c.(func(*master, map[int]bool) error)
		stillRunning = d.(func(*master) bool)
	}(testMaster, reloadMaster, confirmReload, stillRunning)
	testMaster = func(context.Context, *master, io.Writer) error { logTo("test"); return testErr }
	reloadMaster = func(context.Context, *master, io.Writer) error { logTo("reload"); return nil }
	confirmReload = func(*master, map[int]bool) error { return confirm }
	stillRunning = func(*master) bool { return true }
	var out bytes.Buffer
	err := relocate(context.Background(), catalog.In("en"), req, []*master{m}, read, &out)
	return out.String(), err
}

func configs(t *testing.T, root string) string {
	return read(t, root+"/httpd.conf") + read(t, root+"/avail/a.conf")
}

// The note goes on a line of its own above each run of consecutive changed
// directives, indented as the first is, since Apache reads `#` as a comment
// only at the start of a line. A second line in the note never reaches the
// file.
func TestRelocateLeavesTheNoteAboveEachChangedLine(t *testing.T) {
	root, m, rd := certbotHost(t)
	req := moveOut(t, root, m, rd)
	req.Note = "now managed by easySSL\nSSLEngine off"
	if out, err := runRelocate(t, root, req, m, rd, nil, nil); err != nil {
		t.Fatalf("relocate: %v\n%s", err, out)
	}
	want := "  ServerName a.test\n  # now managed by easySSL\n  SSLCertificateFile \"" + root + "/easyssl/a/certificate.pem\"\n" +
		"  SSLCertificateKeyFile '" + root + "/easyssl/a/key.pem'\n"
	if got := read(t, root+"/httpd.conf"); !strings.Contains(got, want) {
		t.Errorf("httpd.conf:\n%s\nwant:\n%s", got, want)
	}
	want = "  ServerName a.test\n\t# now managed by easySSL\n\tSSLCertificateFile " + root + "/easyssl/a/certificate.pem\n" +
		"  SSLCertificateKeyFile " + root + "/easyssl/a/key.pem\n"
	if got := read(t, root+"/avail/a.conf"); !strings.Contains(got, want) || strings.Contains(got, "SSLEngine") {
		t.Errorf("the included file:\n%s\nwant:\n%s", got, want)
	}
}

func TestRelocateRewritesTheConfirmedLines(t *testing.T) {
	root, m, rd := certbotHost(t)
	req := moveOut(t, root, m, rd)
	if len(req.References) != 4 {
		t.Fatalf("references %+v, want both directives in both files", req.References)
	}
	out, err := runRelocate(t, root, req, m, rd, nil, nil)
	if err != nil {
		t.Fatalf("relocate: %v\n%s", err, out)
	}
	if got := read(t, root+"/httpd.conf"); !strings.Contains(got, "  SSLCertificateFile \""+root+"/easyssl/a/certificate.pem\"\n  SSLCertificateKeyFile '"+root+"/easyssl/a/key.pem'\n") {
		t.Errorf("httpd.conf lost its quoting or was not changed:\n%s", got)
	}
	if got := read(t, root+"/avail/a.conf"); !strings.Contains(got, "\tSSLCertificateFile "+root+"/easyssl/a/certificate.pem\n  SSLCertificateKeyFile "+root+"/easyssl/a/key.pem\n") {
		t.Errorf("the included file:\n%s", got)
	}
	if fi, err := os.Lstat(root + "/sites/a.conf"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the Include's symlink was replaced by a file")
	}
	if fi, _ := os.Stat(root + "/avail/a.conf"); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %04o, want the file's 0640 kept", fi.Mode().Perm())
	}
	if got := read(t, root+"/log"); got != "test\nreload\n" {
		t.Errorf("steps ran as %q, want test then reload", got)
	}
	for _, s := range []string{"`" + root + "/sites/a.conf:4`: `le/live/a/fullchain.pem` → `" + root + "/easyssl/a/certificate.pem`", "Changed 4 lines"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestRelocateRefusesWhatWasNotConfirmed(t *testing.T) {
	root, m, rd := certbotHost(t)
	before := configs(t, root)
	full := moveOut(t, root, m, rd)
	short := full
	short.References = full.References[1:]
	if out, err := runRelocate(t, root, short, m, rd, nil, nil); err == nil || !strings.Contains(out, "- found, not confirmed: `"+full.References[0].File) {
		t.Errorf("a reference left out: %v\n%s", err, out)
	}
	if configs(t, root) != before {
		t.Error("a refused move changed the configuration")
	}
	if _, err := os.Stat(root + "/log"); !os.IsNotExist(err) {
		t.Error("a refused move ran a step")
	}
}

func TestRelocateFailedTestPutsTheFilesBack(t *testing.T) {
	root, m, rd := certbotHost(t)
	before := configs(t, root)
	out, err := runRelocate(t, root, moveOut(t, root, m, rd), m, rd, errors.New("exit status 1"), nil)
	if err == nil || !strings.Contains(out, "so nothing was reloaded. The original configuration is back.") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if configs(t, root) != before {
		t.Error("the original configuration was not put back")
	}
	if got := read(t, root+"/log"); got != "test\n" {
		t.Errorf("steps ran as %q, want the test alone", got)
	}
}

// A reload that failed while the master runs puts the files back and
// reloads again.
func TestRelocateFailedReloadPutsTheFilesBackAndReloads(t *testing.T) {
	root, m, rd := certbotHost(t)
	before := configs(t, root)
	out, err := runRelocate(t, root, moveOut(t, root, m, rd), m, rd, nil, errors.New("the reload command exited with status 1"))
	if err == nil || !strings.Contains(out, "Reloading Apache (`pid 1`) failed: the reload command exited with status 1. The original configuration is back.") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if configs(t, root) != before {
		t.Error("the original configuration was not put back")
	}
	if got := read(t, root+"/log"); got != "test\nreload\nreload\n" {
		t.Errorf("steps ran as %q, want test, reload, and the reload of the original", got)
	}
}

func TestRelocateRefusesAConfigurationEditedSinceLoaded(t *testing.T) {
	root, m, rd := certbotHost(t, "/etc/httpd/conf.d/other.conf")
	before := configs(t, root)
	out, err := runRelocate(t, root, moveOut(t, root, m, rd), m, rd, nil, nil)
	if err == nil || !strings.Contains(out, "`/etc/httpd/conf.d/other.conf` changed since Apache (`pid 1`) last loaded its configuration") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if configs(t, root) != before {
		t.Error("a refused move changed the configuration")
	}
}

func TestRelocateRefusesBadDestinations(t *testing.T) {
	root, m, rd := certbotHost(t)
	before := configs(t, root)
	for to, why := range map[string]string{
		"easyssl/a/certificate.pem":      "not an absolute path",
		root + "/easyssl/a/missing.pem":  "no file exists there",
		root + "/easyssl/a/${X}.pem":     "`$`",
		root + "/easyssl/a/certificate.": "no file exists there",
	} {
		req := moveOut(t, root, m, rd)
		req.Moves[0].To = to
		if out, err := runRelocate(t, root, req, m, rd, nil, nil); err == nil || !strings.Contains(out, why) {
			t.Errorf("%s: %v\n%s", to, err, out)
		}
	}
	if configs(t, root) != before {
		t.Error("a refused move changed the configuration")
	}
}

func TestQuoted(t *testing.T) {
	for _, c := range []struct {
		path  string
		first byte
		want  string
	}{
		{"/etc/ssl/a.pem", '/', "/etc/ssl/a.pem"},
		{"/etc/ssl/a.pem", '"', `"/etc/ssl/a.pem"`},
		{"/etc/ssl/a.pem", '\'', "'/etc/ssl/a.pem'"},
		{"/etc/my ssl/a.pem", 'l', `"/etc/my ssl/a.pem"`},
	} {
		if got := quoted(c.path, c.first); got != c.want {
			t.Errorf("quoted(%q, %q) = %s, want %s", c.path, c.first, got, c.want)
		}
	}
}
