package ops

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// One host with every configuration case the Discovery test cases table
// (S12) holds that parsing alone decides, each named by the port the fixture
// scripts give it. What needs a running nginx (the gate's own verdict, the
// reload command per init system) is scan's and is not here.
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

func byCert(targets []SuggestedTarget) map[string]SuggestedTarget {
	out := map[string]SuggestedTarget{}
	for _, s := range targets {
		out[s.PluginSettings[SettingCertificate]] = s
	}
	return out
}

func extra(s SuggestedTarget, label string) string {
	for _, d := range s.PluginExtraData {
		if d.Label == label {
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
				t.Fatalf("%s not suggested", c.cert)
			}
			if loc := extra(s, "Locations"); !strings.Contains(loc, root+"/"+c.file+":") {
				t.Errorf("%s located at %q, want %s", c.cert, loc, c.file)
			}
		}
	})
	t.Run("decoys nginx never loads are absent", func(t *testing.T) {
		if _, ok := got[ssl+"decoy.crt"]; ok {
			t.Fatal("decoy.crt suggested: an unlinked sites-available entry, an orphan snippet or a comment was read")
		}
	})
	t.Run("names come from the certificate, in its order", func(t *testing.T) {
		if d := got[ssl+"confd.crt"].SuggestedDomains; !slices.Equal(d, []string{"a.example.test", "b.example.test", "c.example.test"}) {
			t.Errorf("confd domains %v", d)
		}
		if d := got[ssl+"order.crt"].SuggestedDomains; !slices.Equal(d, []string{"first.example.test", "192.0.2.7", "last.example.test"}) {
			t.Errorf("interleaved SANs %v, want DNS, IP, DNS in encoded order", d)
		}
		if d := got[ssl+"chain.crt"].SuggestedDomains; !slices.Equal(d, []string{"leaf.example.test"}) {
			t.Errorf("fullchain domains %v, want the leaf's only", d)
		}
		nosan, ok := got[ssl+"nosan.crt"]
		if !ok || len(nosan.SuggestedDomains) != 0 || nosan.SuggestedDomains == nil {
			t.Errorf("a certificate with no SAN extension: %+v, want suggested with an empty list", nosan)
		}
	})
	t.Run("http-level certificate is one suggestion", func(t *testing.T) {
		if _, ok := got[ssl+"http.crt"]; !ok {
			t.Fatal("http-level certificate not suggested")
		}
	})
	t.Run("relative path resolves against the configuration directory", func(t *testing.T) {
		s, ok := got[root+"/etc/nginx/certs/relative.crt"]
		if !ok || s.PluginSettings[SettingKey] != root+"/etc/nginx/certs/relative.key" {
			t.Fatalf("relative: %+v", s)
		}
	})
	t.Run("five spellings of one file are one suggestion", func(t *testing.T) {
		s, ok := got[ssl+"many.crt"]
		if !ok {
			t.Fatal("many.crt not suggested under its resolved path")
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
			if k := got[ssl+cert].PluginSettings[SettingKey]; k != ssl+key {
				t.Errorf("%s paired with %s, want %s", cert, k, key)
			}
		}
		if a := extra(got[ssl+"dual-rsa.crt"], "Key algorithm"); a != "RSA 2048" {
			t.Errorf("dual-rsa key algorithm %q", a)
		}
		if a := extra(got[ssl+"dual-ec.crt"], "Key algorithm"); a != "ECDSA P-256" {
			t.Errorf("dual-ec key algorithm %q", a)
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
	t.Run("settings carry the instance's commands", func(t *testing.T) {
		s := got[ssl+"confd.crt"]
		if s.PluginSettings[SettingTest] != "/usr/sbin/nginx -t" || s.PluginSettings[SettingReload] != "systemctl reload nginx.service" {
			t.Fatalf("commands %v", s.PluginSettings)
		}
	})
	t.Run("unchanged host, identical answer", func(t *testing.T) {
		again, againWarnings := analyze([]instance{load(t, 100, config)})
		if !equalTargets(targets, again) || !slices.Equal(warnings, againWarnings) {
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
	if !hasWarning(warnings, "read by 2 nginx instances", "nginx-second.service") {
		t.Fatalf("warnings %q", warnings)
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
		return errors.New(`nginx rejects this configuration, so it was not parsed: cannot load certificate "/missing.crt"`)
	}, in.Exe, in.ConfigPath)
	targets, warnings := analyze([]instance{in})
	if len(targets) != 0 || !hasWarning(warnings, "pid 7", "/missing.crt") {
		t.Fatalf("targets %+v, warnings %q", targets, warnings)
	}
}

func TestDiscoverDeclaresFourSettings(t *testing.T) {
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
}

func hasWarning(warnings []string, parts ...string) bool {
	for _, w := range warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			return true
		}
	}
	return false
}

func equalTargets(a, b []SuggestedTarget) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].PluginSettings[SettingCertificate] != b[i].PluginSettings[SettingCertificate] ||
			extra(a[i], "Locations") != extra(b[i], "Locations") ||
			!slices.Equal(a[i].SuggestedDomains, b[i].SuggestedDomains) {
			return false
		}
	}
	return true
}
