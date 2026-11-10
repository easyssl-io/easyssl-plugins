package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgAt(t *testing.T) {
	for _, c := range []struct {
		line, name, value string
		span              string // what [start:end] covers
		ok                bool
	}{
		{"SSLCertificateFile /etc/a.crt", "SSLCertificateFile", "/etc/a.crt", "/etc/a.crt", true},
		{"  sslcertificatefile\t/etc/a.crt  # no comments here", "SSLCertificateFile", "/etc/a.crt", "/etc/a.crt", true},
		{`SSLCertificateFile "/etc/my dir/a.crt"`, "SSLCertificateFile", "/etc/my dir/a.crt", `"/etc/my dir/a.crt"`, true},
		{`SSLCertificateFile '${D}/a.crt'`, "SSLCertificateFile", "${D}/a.crt", `'${D}/a.crt'`, true},
		{`SSLCertificateFile "a\"b"`, "SSLCertificateFile", `a"b`, `"a\"b"`, true},
		{"SSLCertificateFile /a.crt\r", "SSLCertificateFile", "/a.crt", "/a.crt", true},
		{"SSLCertificateKeyFile /etc/a.key", "SSLCertificateFile", "", "", false},
		{"SSLCertificateFile", "SSLCertificateFile", "", "", false},
		{`SSLCertificateFile "/unterminated`, "SSLCertificateFile", "", "", false},
	} {
		v, start, end, ok := argAt(c.line, c.name)
		if ok != c.ok || v != c.value || (ok && c.line[start:end] != c.span) {
			t.Errorf("argAt(%q) = %q %d:%d %v, want %q covering %q", c.line, v, start, end, ok, c.value, c.span)
		}
	}
}

// caseOf is one Apache master whose configuration is the dump given, with
// @ROOT@ replaced by root, and its virtual hosts listing.
func caseOf(root, dump, vhosts string) (*master, configReader) {
	m := &master{PID: 1, Exe: "/usr/sbin/httpd", ServerRoot: root, PidFile: root + "/httpd.pid", PidFilePID: 1, Graceful: true}
	return m, func(*master) (*serverCfg, []string, error) {
		s := parseDump(strings.ReplaceAll(dump, "@ROOT@", root))
		parseVhosts(strings.ReplaceAll(vhosts, "@ROOT@", root), s)
		return s, nil, nil
	}
}

// A reference holds the argument as the file writes it, ${VAR} and quotes
// as they are, not as httpd's dump reports it.
func TestReferencesAreAsWritten(t *testing.T) {
	root := ownedDir(t)
	conf := "Listen 9441\n<VirtualHost *:9441>\n  SSLCertificateFile \"${D}/a.crt\"\n  sslcertificatekeyfile 'k dir/a.key'\n</VirtualHost>\n"
	if err := os.WriteFile(filepath.Join(root, "httpd.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	m, read := caseOf(root, `# In file: @ROOT@/httpd.conf
#   1:
Listen 9441
#   2:
<VirtualHost *:9441>
  #   3:
  SSLCertificateFile @ROOT@/a.crt
  #   4:
  SSLCertificateKeyFile "@ROOT@/k dir/a.key"
</VirtualHost>
`, "*:9441                 a.test (@ROOT@/httpd.conf:2)\n")
	targets, warnings := analyze([]*master{m}, read)
	if len(targets) != 1 || len(warnings) != 0 {
		t.Fatalf("targets %+v, warnings %q", targets, warnings)
	}
	refs := targets[0].References
	if len(refs) != 2 || refs[0].Value != "${D}/a.crt" || refs[0].Line != 3 || refs[1].Value != "k dir/a.key" || refs[1].Setting != SettingKey {
		t.Fatalf("references %+v", refs)
	}
}

// A certificate held in a token is no Target, so it is a top-level warning; a
// key held in one is the certificate's own warning, and no reference.
func TestTokensAreNotFiles(t *testing.T) {
	root := ownedDir(t)
	m, read := caseOf(root, `# In file: @ROOT@/httpd.conf
#   1:
Listen 9441
#   2:
Listen 9442
#   3:
<VirtualHost *:9441>
  #   4:
  SSLCertificateFile pkcs11:token=web;object=c
  #   5:
  SSLCertificateKeyFile pkcs11:token=web;object=k
</VirtualHost>
#   6:
<VirtualHost *:9442>
  #   7:
  SSLCertificateFile @ROOT@/b.crt
  #   8:
  SSLCertificateKeyFile pkcs11:token=web;object=b
</VirtualHost>
`, "*:9441                 a.test (@ROOT@/httpd.conf:3)\n*:9442                 b.test (@ROOT@/httpd.conf:6)\n")
	targets, warnings := analyze([]*master{m}, read)
	if len(warnings) != 1 || !strings.Contains(warnings[0]["en"], "`pkcs11:token=web;object=c` (`"+root+"/httpd.conf:4`) names a certificate held in a token") {
		t.Fatalf("warnings %q", warnings)
	}
	if len(targets) != 1 || targets[0].Settings[SettingCertificate] != root+"/b.crt" {
		t.Fatalf("targets %+v", targets)
	}
	found := false
	for _, w := range targets[0].Warnings {
		found = found || strings.HasPrefix(w["en"], "Its key `pkcs11:token=web;object=b` (`"+root+"/httpd.conf:8`) is held in a token")
	}
	if !found || len(targets[0].References) != 1 || targets[0].References[0].Setting != SettingCertificate {
		t.Fatalf("b.crt: %+v", targets[0])
	}
}

// httpd's dump prints arguments as written, so both quotes are read the way
// httpd reads them.
func TestTokens(t *testing.T) {
	for in, want := range map[string]string{
		`SSLCertificateFile /etc/a.crt`:           "SSLCertificateFile|/etc/a.crt",
		`SSLCertificateKeyFile '/etc/my key.pem'`: "SSLCertificateKeyFile|/etc/my key.pem",
		`SSLCertificateFile "/etc/a.crt"`:         "SSLCertificateFile|/etc/a.crt",
		`VirtualHost *:443 [::1]:443`:             "VirtualHost|*:443|[::1]:443",
		`Header set X "a \"b\" c"`:                `Header|set|X|a "b" c`,
		"SSLEngine\ton":                           "SSLEngine|on",
		`ServerAlias it's`:                        "ServerAlias|it's",
	} {
		if got := strings.Join(tokens(in), "|"); got != want {
			t.Errorf("tokens(%q) = %q, want %q", in, got, want)
		}
	}
}
