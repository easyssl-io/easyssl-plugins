package ops

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easyssl-io/easyssl-contract/contracttest"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/l10n/l10ncheck"
)

// The cases under testdata/cases are what httpd 2.4 itself reported for the
// configurations testdata/setup.sh starts, one Apache master each, as
// testdata/capture.sh recorded them: its
// DUMP_CONFIG with mod_info loaded (config), its DUMP_VHOSTS (vhosts), and
// what each certificate or key file it names held (files), with /srv/cases
// replaced by @ROOT@. The test recreates those files under a temporary root,
// with fresh keys that pair the way the originals did, and compares what
// discover answers with testdata/discover.golden.

// caseIPs are the addresses of the VM the cases ran on, which decide which
// virtual hosts an exact-address one shadows.
var caseIPs = []string{"127.0.0.1", "192.168.5.15", "::1"}

func TestDiscoverCases(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Writable by its owner alone, or every file under it is unsafe to write
	// (writerFor), whatever the umask the test runs with.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	defer func(f func() []string) { localIPs = f }(localIPs)
	localIPs = func() []string { return caseIPs }

	entries, err := os.ReadDir("testdata/cases")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.Signer{}
	var masters []*master
	dumps := map[*master][2]string{}
	for i, e := range entries {
		dir := filepath.Join("testdata/cases", e.Name())
		materialize(t, root, filepath.Join(dir, "files"), keys)
		read := func(name string) string {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			return strings.ReplaceAll(string(b), "@ROOT@", root)
		}
		m := &master{
			PID: 1000 + i, Exe: "/opt/httpd/bin/httpd", ServerRoot: "/opt/httpd",
			Replay:  []string{"-f", filepath.Join(root, e.Name(), "httpd.conf")},
			PidFile: filepath.Join(root, e.Name(), "httpd.pid"), PidFilePID: 1000 + i,
			Graceful: true,
		}
		masters = append(masters, m)
		dumps[m] = [2]string{read("config"), read("vhosts")}
	}
	reader := func(m *master) (*serverCfg, []string, error) {
		s := parseDump(dumps[m][0])
		parseVhosts(dumps[m][1], s)
		var changed []string
		if strings.HasSuffix(m.PidFile, "/P/httpd.pid") { // the case edits its configuration after the start
			changed = []string{filepath.Join(root, "P/httpd.conf")}
		}
		return s, changed, nil
	}
	targets, warnings := analyze(masters, reader)

	var b strings.Builder
	for _, tg := range targets {
		s := tg.Settings
		b.WriteString("SUGGEST " + s[SettingCertificate] + "\n")
		b.WriteString("  key: " + s[SettingKey] + "\n  test: " + s[SettingTest] + "\n  reload: " + s[SettingReload] + "\n")
		b.WriteString("  " + tg.ExtraData[0].Value + "\n")
	}
	for _, w := range warnings {
		b.WriteString("WARN " + w.In(l10n.English) + "\n")
	}
	got := strings.ReplaceAll(b.String(), root, "@ROOT@")
	contracttest.GoldenFile(t, "testdata/discover.golden", []byte(got))

	// Every warning reads in Spanish too, with nothing left untranslated.
	for _, w := range warnings {
		if es := w.In("es"); es == w.In(l10n.English) {
			t.Errorf("a warning has no Spanish: %s", es)
		}
	}
}

// materialize writes the files a case's manifest lists. A line reads
// "<path> <kind>", kind being comma-separated: cert-rsa or cert-ec for a
// certificate, key for a private key, encrypted for a passphrase-protected
// one, missing for a path with no file, and an 8-hex key identity that makes
// files sharing it hold the same key.
func materialize(t *testing.T, root, manifest string, keys map[string]crypto.Signer) {
	t.Helper()
	f, err := os.Open(manifest)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || fields[1] == "missing" {
			continue
		}
		path := strings.ReplaceAll(fields[0], "@ROOT@", root)
		if _, err := os.Stat(path); err == nil {
			continue // named by more than one case
		}
		kinds := map[string]bool{}
		var id, alg string
		for _, k := range strings.Split(fields[1], ",") {
			switch {
			case k == "cert-rsa" || k == "cert-ec":
				alg = strings.TrimPrefix(k, "cert-")
			case len(k) == 8:
				id = k
			default:
				kinds[k] = true
			}
		}
		var out []byte
		if kinds["encrypted"] {
			out = pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("not a real key")})
		} else {
			key := keys[id]
			if key == nil {
				key = newKey(t, alg)
				keys[id] = key
			}
			if alg != "" {
				out = append(out, selfSigned(t, key, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))+".test")...)
			}
			if kinds["key"] {
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func newKey(t *testing.T, alg string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	if alg == "rsa" {
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfSigned(t *testing.T, key crypto.Signer, name string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestReplayOf(t *testing.T) {
	for _, c := range []struct{ argv, want string }{
		{"/usr/sbin/httpd -k start", ""},
		{"/usr/sbin/httpd -DFOREGROUND", "-D FOREGROUND"},
		{"/opt/httpd/bin/httpd -f /srv/x/httpd.conf -k start", "-f /srv/x/httpd.conf"},
		// The order is fixed whatever the argv's, and -e, -E and -k values
		// are skipped with them.
		{"/usr/sbin/httpd -c Listen_8443 -e debug -DHAND -d /etc/h -f conf/h.conf -C X", "-d /etc/h -f conf/h.conf -D HAND -C X -c Listen_8443"},
	} {
		got := strings.Join(replayOf(strings.Fields(c.argv)), " ")
		if got != c.want {
			t.Errorf("replayOf(%q) = %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/sbin/apache2":    "/usr/sbin/apache2",
		"/srv/my site/h.conf":  "'/srv/my site/h.conf'",
		"a;rm -rf /":           "'a;rm -rf /'",
		"it's":                 `'it'\''s'`,
		"":                     "''",
		"LoadModule x /m/x.so": "'LoadModule x /m/x.so'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestCatalog(t *testing.T) { l10ncheck.Check(t, ".", "locales") }

func TestURIRe(t *testing.T) {
	for v, want := range map[string]bool{
		"pkcs11:token=web;object=k;type=private": true,
		"/etc/ssl/k.pem":                         false,
		"conf/ssl/k.pem":                         false,
		"C:/x.pem":                               false,
	} {
		if got := uriRe.MatchString(v); got != want {
			t.Errorf("uriRe(%q) = %v, want %v", v, got, want)
		}
	}
}
