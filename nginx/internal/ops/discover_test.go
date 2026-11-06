package ops

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/l10n/l10ncheck"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// One host with every configuration case that parsing alone decides, each named
// by the port the fixture scripts give it. What needs a running nginx (the
// gate's own verdict, the reload command per init system) is scan's and is not
// here.
func hostTree(t *testing.T) (string, map[string]material) {
	t.Helper()
	m := map[string]material{
		"inline":   issue(t, "ec", "inline.example.test"),
		"confd":    issue(t, "ec", "a.example.test", "b.example.test", "c.example.test"),
		"sites":    issue(t, "ec", "sites.example.test"),
		"snippet":  issue(t, "ec", "snippet.example.test"),
		"decoy":    issue(t, "ec", "decoy.example.test"),
		"http":     issue(t, "ec", "http.example.test"),
		"relative": issue(t, "ec", "relative.example.test"),
		"many":     issue(t, "ec", "many.example.test"),
		"dualRSA":  issue(t, "rsa", "dual.example.test"),
		"dualEC":   issue(t, "ec", "dual.example.test"),
		"crossRSA": issue(t, "rsa", "cross.example.test"),
		"crossEC":  issue(t, "ec", "cross.example.test"),
		"rsa1":     issue(t, "rsa", "one.example.test"),
		"rsa2":     issue(t, "rsa", "two.example.test"),
		"chain":    issue(t, "ec", "leaf.example.test"),
		"other":    issue(t, "ec", "unrelated.example.test"),
		"order":    issue(t, "ec", "first.example.test", "192.0.2.7", "last.example.test"),
		"nosan":    issue(t, "ec"),
		"twokeys":  issue(t, "ec", "twokeys.example.test"),
	}
	files := map[string]string{
		"etc/nginx/nginx.conf": `
http {
    ssl_certificate /ROOT/ssl/http.crt;
    ssl_certificate_key /ROOT/ssl/http.key;
    server { listen 9008 ssl; }
    server { listen 9001 ssl; server_name inline.example.test; ssl_certificate /ROOT/ssl/inline.crt; ssl_certificate_key /ROOT/ssl/inline.key; }
    include conf.d/*.conf;
    include sites-enabled/*;
    # ssl_certificate /ROOT/ssl/decoy.crt;
}
`,
		"etc/nginx/conf.d/site.conf": `
server { listen 9002 ssl; server_name a.example.test b.example.test c.example.test;
    ssl_certificate /ROOT/ssl/confd.crt; ssl_certificate_key /ROOT/ssl/confd.key; }
include tls-snippets/*.conf;
server { listen 9009 ssl; ssl_certificate certs/relative.crt; ssl_certificate_key certs/relative.key; }
server { listen 9018 ssl; ssl_certificate /ROOT/live/many.crt; ssl_certificate_key /ROOT/ssl/many.key; }
server { listen 9019 ssl; ssl_certificate /ROOT/ssl/many-link.crt; ssl_certificate_key /ROOT/ssl/many.key; }
server { listen 9020 ssl; ssl_certificate /ROOT/ssl/../ssl/./many.crt; ssl_certificate_key /ROOT/ssl/many.key; }
server { listen 9021 ssl; ssl_certificate /ROOT/ssl//many.crt; ssl_certificate_key /ROOT/ssl/many.key; }
server { listen 9022 ssl; ssl_certificate certs/many-rel.crt; ssl_certificate_key /ROOT/ssl/many.key; }
server { listen 9007 ssl; ssl_certificate /ROOT/ssl/dual-rsa.crt; ssl_certificate_key /ROOT/ssl/dual-rsa.key;
    ssl_certificate /ROOT/ssl/dual-ec.crt; ssl_certificate_key /ROOT/ssl/dual-ec.key; }
server { listen 9032 ssl; ssl_certificate /ROOT/ssl/cross-rsa.crt; ssl_certificate /ROOT/ssl/cross-ec.crt;
    ssl_certificate_key /ROOT/ssl/cross-ec.key; ssl_certificate_key /ROOT/ssl/cross-rsa.key; }
server { listen 9033 ssl; ssl_certificate /ROOT/ssl/rsa1.crt; ssl_certificate /ROOT/ssl/rsa2.crt;
    ssl_certificate_key /ROOT/ssl/rsa1.key; ssl_certificate_key /ROOT/ssl/rsa2.key; }
server { listen 9031 ssl; ssl_certificate /ROOT/ssl/chain.crt; ssl_certificate_key /ROOT/ssl/chain.key; }
server { listen 443 ssl; ssl_certificate /ROOT/ssl/order.crt; ssl_certificate_key /ROOT/ssl/order.key; }
server { listen 9042 ssl; ssl_certificate /ROOT/ssl/nosan.crt; ssl_certificate_key /ROOT/ssl/nosan.key; }
server { listen 9040 ssl; ssl_certificate /ROOT/ssl/twokeys.crt; ssl_certificate_key /ROOT/ssl/twokeys-a.key; }
server { listen 9041 ssl; ssl_certificate /ROOT/ssl/twokeys.crt; ssl_certificate_key /ROOT/ssl/twokeys-b.key; }
`,
		"etc/nginx/tls-snippets/snippet.conf": `server { listen 9005 ssl; ssl_certificate /ROOT/ssl/snippet.crt; ssl_certificate_key /ROOT/ssl/snippet.key; }`,
		"etc/nginx/sites-available/linked":    `server { listen 9003 ssl; ssl_certificate /ROOT/ssl/sites.crt; ssl_certificate_key /ROOT/ssl/sites.key; }`,
		"etc/nginx/sites-available/unlinked":  `server { listen 9004 ssl; ssl_certificate /ROOT/ssl/decoy.crt; ssl_certificate_key /ROOT/ssl/decoy.key; }`,
		"etc/nginx/sites-enabled/linked":      "->../sites-available/linked",
		"etc/nginx/tls-unused/orphan.conf":    `server { listen 9011 ssl; ssl_certificate /ROOT/ssl/decoy.crt; ssl_certificate_key /ROOT/ssl/decoy.key; }`,
		"etc/nginx/certs/many-rel.crt":        "->../../../ssl/many.crt",
		"ssl/many-link.crt":                   "->many.crt",
		"live":                                "->ssl",
	}
	for name, file := range map[string]string{
		"inline": "ssl/inline", "confd": "ssl/confd", "sites": "ssl/sites", "snippet": "ssl/snippet",
		"decoy": "ssl/decoy", "http": "ssl/http", "relative": "etc/nginx/certs/relative", "many": "ssl/many",
		"dualRSA": "ssl/dual-rsa", "dualEC": "ssl/dual-ec", "crossRSA": "ssl/cross-rsa", "crossEC": "ssl/cross-ec",
		"rsa1": "ssl/rsa1", "rsa2": "ssl/rsa2", "chain": "ssl/chain", "order": "ssl/order", "nosan": "ssl/nosan",
		"twokeys": "ssl/twokeys",
	} {
		files[file+".crt"] = m[name].cert
		files[file+".key"] = m[name].key
	}
	// A fullchain whose second certificate is unrelated to the leaf.
	files["ssl/chain.crt"] = m["chain"].cert + m["other"].cert
	// Two key files with identical bytes, named by two servers.
	files["ssl/twokeys-a.key"] = m["twokeys"].key
	files["ssl/twokeys-b.key"] = m["twokeys"].key
	delete(files, "ssl/twokeys.key")
	root := tree(t, files)
	for _, p := range []string{"etc/nginx/nginx.conf", "etc/nginx/conf.d/site.conf", "etc/nginx/tls-snippets/snippet.conf",
		"etc/nginx/sites-available/linked", "etc/nginx/sites-available/unlinked", "etc/nginx/tls-unused/orphan.conf"} {
		replaceRoot(t, root, p)
	}
	return root, m
}

func replaceRoot(t *testing.T, root, p string) {
	t.Helper()
	full := root + "/" + p
	b, err := readFile(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(full, strings.ReplaceAll(b, "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
}

func byCert(targets []DiscoveredTarget) map[string]DiscoveredTarget {
	out := map[string]DiscoveredTarget{}
	for _, s := range targets {
		out[s.Settings[SettingCertificate]] = s
	}
	return out
}

// domainsOf and keyTypeOf read the discovered certificate, nil and empty
// when none was reported.
func domainsOf(t DiscoveredTarget) []string {
	if t.Certificate == nil {
		return nil
	}
	return t.Certificate.Domains
}

func keyTypeOf(t DiscoveredTarget) string {
	if t.Certificate == nil {
		return ""
	}
	return t.Certificate.KeyType
}

func extra(s DiscoveredTarget, label string) string {
	for _, d := range s.ExtraData {
		if d.Label["en"] == label {
			return d.Value
		}
	}
	return ""
}

func TestDiscoverCases(t *testing.T) {
	root, _ := hostTree(t)
	config := root + "/etc/nginx/nginx.conf"
	targets, warnings := analyze([]instance{load(t, 100, config)})
	got := byCert(targets)
	ssl := root + "/ssl/"

	t.Run("where the configuration lives", func(t *testing.T) {
		for _, c := range []struct{ cert, file string }{
			{"inline.crt", "etc/nginx/nginx.conf"},
			{"confd.crt", "etc/nginx/conf.d/site.conf"},
			{"sites.crt", "etc/nginx/sites-enabled/linked"},
			{"snippet.crt", "etc/nginx/tls-snippets/snippet.conf"},
		} {
			s, ok := got[ssl+c.cert]
			if !ok {
				t.Fatalf("%s not reported", c.cert)
			}
			if loc := extra(s, "Locations"); !strings.Contains(loc, "`pid 100:"+root+"/"+c.file+":") {
				t.Errorf("%s located at %q, want %s", c.cert, loc, c.file)
			}
		}
	})
	t.Run("decoys nginx never loads are absent", func(t *testing.T) {
		if _, ok := got[ssl+"decoy.crt"]; ok {
			t.Fatal("decoy.crt reported: an unlinked sites-available entry, an orphan snippet or a comment was read")
		}
	})
	t.Run("names come from the certificate, in its order", func(t *testing.T) {
		if d := domainsOf(got[ssl+"confd.crt"]); !slices.Equal(d, []string{"a.example.test", "b.example.test", "c.example.test"}) {
			t.Errorf("confd domains %v", d)
		}
		if d := domainsOf(got[ssl+"order.crt"]); !slices.Equal(d, []string{"first.example.test", "192.0.2.7", "last.example.test"}) {
			t.Errorf("interleaved SANs %v, want DNS, IP, DNS in encoded order", d)
		}
		if d := domainsOf(got[ssl+"chain.crt"]); !slices.Equal(d, []string{"leaf.example.test"}) {
			t.Errorf("fullchain domains %v, want the leaf's only", d)
		}
		nosan, ok := got[ssl+"nosan.crt"]
		if !ok || nosan.Certificate == nil || len(nosan.Certificate.Domains) != 0 || nosan.Certificate.Domains == nil {
			t.Errorf("a certificate with no SAN extension: %+v, want reported with an empty list", nosan)
		}
	})
	t.Run("http-level certificate is one discovered Target", func(t *testing.T) {
		if _, ok := got[ssl+"http.crt"]; !ok {
			t.Fatal("http-level certificate not reported")
		}
	})
	t.Run("relative path resolves against the configuration directory", func(t *testing.T) {
		s, ok := got[root+"/etc/nginx/certs/relative.crt"]
		if !ok || s.Settings[SettingKey] != root+"/etc/nginx/certs/relative.key" {
			t.Fatalf("relative: %+v", s)
		}
	})
	t.Run("five spellings of one file are one suggestion", func(t *testing.T) {
		s, ok := got[ssl+"many.crt"]
		if !ok {
			t.Fatal("many.crt not reported under its resolved path")
		}
		if n := strings.Count(extra(s, "Locations"), "\n") + 1; n != 5 {
			t.Fatalf("many.crt has %d locations, want 5:\n%s", n, extra(s, "Locations"))
		}
	})
	t.Run("dual certificates pair by algorithm", func(t *testing.T) {
		for cert, key := range map[string]string{
			"dual-rsa.crt": "dual-rsa.key", "dual-ec.crt": "dual-ec.key",
			"cross-rsa.crt": "cross-rsa.key", "cross-ec.crt": "cross-ec.key",
			"rsa1.crt": "rsa1.key", "rsa2.crt": "rsa2.key",
		} {
			if k := got[ssl+cert].Settings[SettingKey]; k != ssl+key {
				t.Errorf("%s paired with %s, want %s", cert, k, key)
			}
		}
		if a := keyTypeOf(got[ssl+"dual-rsa.crt"]); a != "rsa_2048" {
			t.Errorf("dual-rsa key type %q", a)
		}
		if a := keyTypeOf(got[ssl+"dual-ec.crt"]); a != "ec_p256" {
			t.Errorf("dual-ec key type %q", a)
		} // The fingerprint is of the leaf's DER, so it names this exact file
		// and differs between the two halves.
		for _, name := range []string{"dual-rsa.crt", "dual-ec.crt"} {
			der, err := leafDER(ssl + name)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(der)
			if c := got[ssl+name].Certificate; c == nil || c.SHA256 != hex.EncodeToString(sum[:]) {
				t.Errorf("%s fingerprint %+v, want the leaf's SHA-256", name, c)
			}
		}
		if got[ssl+"dual-rsa.crt"].Certificate.SHA256 == got[ssl+"dual-ec.crt"].Certificate.SHA256 {
			t.Error("both halves report one fingerprint")
		}
	})
	t.Run("one certificate with two key files is a warning", func(t *testing.T) {
		if _, ok := got[ssl+"twokeys.crt"]; ok {
			t.Fatal("twokeys.crt suggested")
		}
		if !hasWarning(warnings, "twokeys.crt", "same bytes") {
			t.Fatalf("no key-conflict warning saying the bytes match: %q", warnings)
		}
	})
	t.Run("the locations label is translated, its value is not", func(t *testing.T) {
		d := got[ssl+"confd.crt"].ExtraData[0]
		if d.Label["en"] != "Locations" || d.Label["es"] != "Ubicaciones" {
			t.Fatalf("label %q", d.Label)
		}
	})
	t.Run("settings carry the instance's commands", func(t *testing.T) {
		s := got[ssl+"confd.crt"]
		if s.Settings[SettingTest] != "/usr/sbin/nginx -t" || s.Settings[SettingReload] != "systemctl reload nginx.service" {
			t.Fatalf("commands %v", s.Settings)
		}
	})
	t.Run("unchanged host, identical answer", func(t *testing.T) {
		again, againWarnings := analyze([]instance{load(t, 100, config)})
		if !equalTargets(targets, again) || !slices.EqualFunc(warnings, againWarnings, maps.Equal[l10n.Text, l10n.Text]) {
			t.Fatal("two runs on an unchanged host disagree")
		}
	})
}

func TestSharedCertificateIsAWarning(t *testing.T) {
	a := issue(t, "ec", "shared.example.test")
	root := tree(t, map[string]string{
		"one/nginx.conf": `http { server { listen 8444 ssl; ssl_certificate /ROOT/shared.crt; ssl_certificate_key /ROOT/shared.key; } }`,
		"two/nginx.conf": `http { server { listen 8445 ssl; ssl_certificate /ROOT/shared.crt; ssl_certificate_key /ROOT/shared.key; } }`,
		"shared.crt":     a.cert,
		"shared.key":     a.key,
	})
	replaceRoot(t, root, "one/nginx.conf")
	replaceRoot(t, root, "two/nginx.conf")
	one, two := load(t, 100, root+"/one/nginx.conf"), load(t, 200, root+"/two/nginx.conf")
	two.Reload = "systemctl reload nginx-second.service"
	targets, warnings := analyze([]instance{two, one})
	if len(targets) != 0 {
		t.Fatalf("a certificate read by two masters was suggested: %+v", targets)
	}
	if !hasWarning(warnings, "read by 2 nginx instances", "`pid 200`, reloaded with `systemctl reload nginx-second.service`, at `") {
		t.Fatalf("warnings %q", warnings)
	}
	// The same warning in Spanish: the sentence and the words inside each
	// listed instance are translated, and what was found on the host is not.
	es := warnings[0]["es"]
	for _, want := range []string{
		"lo leen 2 instancias de nginx",
		"`pid 200`, que se recarga con `systemctl reload nginx-second.service`, en `" + root + "/two/nginx.conf:1`",
		"`" + root + "/shared.crt`",
	} {
		if !strings.Contains(es, want) {
			t.Errorf("the Spanish warning lacks %q: %s", want, es)
		}
	}
	if es == warnings[0]["en"] || strings.Contains(es, "reloaded with") || strings.Contains(es, "{") {
		t.Errorf("the Spanish warning is not wholly Spanish: %s", es)
	}
}

func TestRejectedConfigurationIsAWarning(t *testing.T) {
	a := issue(t, "ec", "ok.example.test")
	root := tree(t, map[string]string{
		"nginx.conf": `http { server { listen 9001 ssl; ssl_certificate /ROOT/ok.crt; ssl_certificate_key /ROOT/ok.key; } }`,
		"ok.crt":     a.cert, "ok.key": a.key,
	})
	replaceRoot(t, root, "nginx.conf")
	in := instance{PID: 7, Exe: "/usr/sbin/nginx", ConfigPath: root + "/nginx.conf"}
	in.Certs, in.CertsErr = certificates(func(string, string) error {
		return &rejectedError{reason: `cannot load certificate "/missing.crt"`}
	}, in.Exe, in.ConfigPath)
	targets, warnings := analyze([]instance{in})
	if len(targets) != 0 || !hasWarning(warnings, "pid 7", "nginx rejects this configuration", `cannot load certificate "/missing.crt"`) {
		t.Fatalf("targets %+v, warnings %q", targets, warnings)
	}
	// nginx's own reason is quoted as nginx wrote it, in every language.
	if es := warnings[0]["es"]; !strings.Contains(es, "nginx rechaza esta configuración") || !strings.Contains(es, `cannot load certificate "/missing.crt"`) {
		t.Fatalf("Spanish warning %q", es)
	}
}

func TestDescribeIsTheIdentityAndTheDeclarations(t *testing.T) {
	d := Describe()
	if d.ContractVersion != plugincontractVersion || d.Name != Name || d.Version == "" {
		t.Fatalf("describe identity = %q %q %q", d.ContractVersion, d.Name, d.Version)
	}
	if d.Description["en"] == "" || d.Description["es"] == "" || d.Description["es"] == d.Description["en"] {
		t.Fatalf("the description needs English and Spanish of its own: %q", d.Description)
	}
	if !slices.EqualFunc(d.Declarations, declarations(), func(a, b SettingDeclaration) bool { return a.Key == b.Key }) {
		t.Fatal("describe does not declare the settings deploy reads")
	}
	if err := plugincontract.ValidateDescribe(d); err != nil {
		t.Fatalf("the Agent would refuse this answer: %v", err)
	}
}

func TestDescribeDeclaresFourSettings(t *testing.T) {
	d := declarations()
	var keys []string
	for _, s := range d {
		keys = append(keys, s.Key)
	}
	if !slices.Equal(keys, []string{SettingCertificate, SettingKey, SettingTest, SettingReload}) {
		t.Fatalf("keys %v", keys)
	}
	if !d[0].Identity || !d[0].Summary || d[1].Identity {
		t.Fatal("ssl_certificate alone must be the identity and the summary")
	}
	// A directive name is a literal and is not translated; everything else
	// has Spanish of its own.
	for _, s := range d[:2] {
		if len(s.Label) != 1 || s.Label["en"] != s.Key {
			t.Errorf("the label of %s is %q, want the directive name in English alone", s.Key, s.Label)
		}
	}
	for _, s := range d {
		if s.Description["es"] == "" || s.Description["es"] == s.Description["en"] {
			t.Errorf("the description of %s has no Spanish of its own", s.Key)
		}
	}
	if d[3].Label["en"] != "Reload command" || d[3].Label["es"] != "Comando de recarga" {
		t.Errorf("reload label %q", d[3].Label)
	}
	if err := plugincontract.ValidateSettings(d); err != nil {
		t.Fatal(err)
	}
}

func TestCatalog(t *testing.T) { l10ncheck.Check(t, ".", "locales") }

// hasWarning reports whether one warning's English text holds every part.
func hasWarning(warnings []l10n.Text, parts ...string) bool {
	for _, w := range warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w["en"], p)
		}
		if ok {
			return true
		}
	}
	return false
}

func equalTargets(a, b []DiscoveredTarget) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Settings[SettingCertificate] != b[i].Settings[SettingCertificate] ||
			extra(a[i], "Locations") != extra(b[i], "Locations") ||
			!slices.Equal(domainsOf(a[i]), domainsOf(b[i])) || keyTypeOf(a[i]) != keyTypeOf(b[i]) {
			return false
		}
	}
	return true
}
