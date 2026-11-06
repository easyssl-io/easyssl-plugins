package ops

import (
	"os"
	"strings"
	"testing"
)

// The places deploy checks after the reload, from a configuration with the
// cases endpoints.go names.
func TestEndpointsFor(t *testing.T) {
	root := tree(t, map[string]string{
		"snippet.conf": `ssl_certificate /ROOT/a.crt; ssl_certificate_key /ROOT/a.key;`,
		"nginx.conf": `
http {
  ssl_certificate /ROOT/http.crt; ssl_certificate_key /ROOT/http.key;
  server { listen 443 ssl; server_name a.test www.a.test; include /ROOT/snippet.conf; }
  server { listen 443 ssl; server_name a.test; ssl_certificate /ROOT/shadowed.crt; ssl_certificate_key /ROOT/s.key; }
  server { listen 443 ssl default_server; server_name _; ssl_certificate /ROOT/default.crt; ssl_certificate_key /ROOT/d.key; }
  server { listen 443 ssl; server_name ~^x$; ssl_certificate /ROOT/nameless.crt; ssl_certificate_key /ROOT/n.key; }
  server { listen 8443 ssl; listen [::]:8443 ssl; server_name *.wild.test; }
  server { listen 9443 ssl proxy_protocol; listen 10443; listen unix:/run/x.sock ssl; server_name p.test;
           ssl_certificate /ROOT/p.crt; ssl_certificate_key /ROOT/p.key; }
  server { listen 192.0.2.1:443 ssl; server_name dual.test;
           ssl_certificate /ROOT/rsa.crt; ssl_certificate_key /ROOT/rsa.key;
           ssl_certificate /ROOT/ec.crt; ssl_certificate_key /ROOT/ec.key; }
}
stream { server { listen 5443 ssl; ssl_certificate /ROOT/stream.crt; ssl_certificate_key /ROOT/st.key; } }
`,
	})
	for _, f := range []string{"nginx.conf", "snippet.conf"} {
		if err := writeFile(root+"/"+f, strings.ReplaceAll(content(t, root+"/"+f), "/ROOT", root)); err != nil {
			t.Fatal(err)
		}
	}
	servers, err := serversOf(root + "/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	for cert, want := range map[string]string{
		"a.crt":        "127.0.0.1:443 sni=a.test",                                                          // through an include
		"shadowed.crt": "",                                                                                  // a.test belongs to the server before it
		"default.crt":  "127.0.0.1:443 sni=(none)",                                                          // default_server, no usable name
		"nameless.crt": "",                                                                                  // a regex name and not the default
		"http.crt":     "127.0.0.1:8443 sni=easyssl-check.wild.test [::1]:8443 sni=easyssl-check.wild.test", // inherited
		"p.crt":        "",                                                                                  // proxy_protocol, no ssl, a socket
		"rsa.crt":      "192.0.2.1:443 sni=dual.test key=RSA",
		"stream.crt":   "127.0.0.1:5443 sni=(none)",
	} {
		alg := "ECDSA"
		if cert == "rsa.crt" {
			alg = "RSA"
		}
		var got []string
		for _, e := range endpointsFor(servers, root+"/"+cert, alg) {
			got = append(got, e.String())
		}
		if g := strings.Join(got, " "); g != want {
			t.Errorf("%s: %q, want %q", cert, g, want)
		}
	}
}

// A wildcard listen is not checked at loopback when another server listens
// on loopback at that port, since that one answers loopback connections.
func TestEndpointsForLoopbackListen(t *testing.T) {
	root := tree(t, map[string]string{"nginx.conf": `http {
  server { listen 443 ssl; server_name a.test; ssl_certificate /ROOT/a.crt; ssl_certificate_key /ROOT/a.key; }
  server { listen 127.0.0.1:443 ssl; server_name b.test; ssl_certificate /ROOT/b.crt; ssl_certificate_key /ROOT/b.key; } }`})
	conf := root + "/nginx.conf"
	if err := writeFile(conf, strings.ReplaceAll(content(t, conf), "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
	servers, err := serversOf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if eps := endpointsFor(servers, root+"/a.crt", "ECDSA"); len(eps) != 0 {
		t.Errorf("a.crt: %v, want none", eps)
	}
	if eps := endpointsFor(servers, root+"/b.crt", "ECDSA"); len(eps) != 1 || eps[0].String() != "127.0.0.1:443 sni=b.test" {
		t.Errorf("b.crt: %v", eps)
	}
}

func TestEmergSince(t *testing.T) {
	log := ownedDir(t) + "/error.log"
	if err := writeFile(log, "old [emerg] 1#1: before\n"); err != nil {
		t.Fatal(err)
	}
	marks := logMarks([]string{log})
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("2026/10/28 01:32:52 [notice] 9#9: signal process started\n" +
		"2026/10/28 01:32:52 [emerg] 27#27: bind() to 0.0.0.0:8460 failed (98: Address in use)\n" +
		"2026/10/28 01:32:53 [emerg] 27#27: bind() to 0.0.0.0:8460 failed (98: Address in use)\n" +
		"2026/10/28 01:32:54 [emerg] 27#27: still could not bind()\n")
	f.Close()
	got := strings.Join(emergSince(marks), " | ")
	if got != "bind() to 0.0.0.0:8460 failed (98: Address in use) | still could not bind()" {
		t.Errorf("got %q", got)
	}
}

// What keeps discovery from suggesting a certificate because a place it is
// served from could not be checked after a reload.
func TestReachProblems(t *testing.T) {
	root := tree(t, map[string]string{"nginx.conf": `
http {
  server { listen 443 ssl; server_name a.test; ssl_certificate /ROOT/a.crt; ssl_certificate_key /ROOT/a.key; }
  server { listen 443 ssl; server_name a.test; ssl_certificate /ROOT/shadowed.crt; ssl_certificate_key /ROOT/s.key; }
  server { listen 443 ssl; server_name ~^x$; ssl_certificate /ROOT/nameless.crt; ssl_certificate_key /ROOT/n.key; }
  server { listen 80; ssl_certificate /ROOT/plain.crt; ssl_certificate_key /ROOT/plain.key; }
  server { listen 9443 ssl proxy_protocol; listen 9444 ssl; server_name p.test; ssl_certificate /ROOT/p.crt; ssl_certificate_key /ROOT/p.key; }
  server { listen 8443 quic; server_name q.test; ssl_certificate /ROOT/q.crt; ssl_certificate_key /ROOT/q.key; }
  server { listen 7443 quic; listen 7443 ssl; server_name h3.test; ssl_certificate /ROOT/h3.crt; ssl_certificate_key /ROOT/h3.key; }
}
stream {
  ssl_certificate /ROOT/unused.crt; ssl_certificate_key /ROOT/unused.key;
  server { listen 5444; proxy_pass 127.0.0.1:1; }
}
`})
	conf := root + "/nginx.conf"
	if err := writeFile(conf, strings.ReplaceAll(content(t, conf), "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
	servers, err := serversOf(conf)
	if err != nil {
		t.Fatal(err)
	}
	for cert, want := range map[string][]string{
		"a.crt":        nil,
		"h3.crt":       nil, // QUIC beside a TCP listen checked there
		"shadowed.crt": {"no client reaches the server at `" + conf + ":4`", "belongs to the server at `" + conf + ":3`"},
		"nameless.crt": {"`" + conf + ":5`", "cannot be checked"},
		"plain.crt":    {"`" + conf + ":6` has no `listen` with `ssl`"},
		"p.crt":        {"PROXY protocol"}, // even though 9444 could be checked
		"q.crt":        {"`" + conf + ":8`", "cannot be checked"},
		"unused.crt":   {"set at `here`", "nothing serves it"},
	} {
		probs := reachProblems(servers, root+"/"+cert, "here")
		if len(want) == 0 {
			if len(probs) != 0 {
				t.Errorf("%s: %q, want none", cert, probs)
			}
			continue
		}
		if len(probs) != 1 || !hasWarning(probs, want...) {
			t.Errorf("%s: %q, want one saying %q", cert, probs, want)
		}
	}
}

// Discovery warns about a certificate served only behind the PROXY protocol
// instead of suggesting it, and keeps suggesting its neighbor.
func TestUncheckableIsNotSuggested(t *testing.T) {
	p, ok := issue(t, "ec", "p.example.test"), issue(t, "ec", "ok.example.test")
	root := tree(t, map[string]string{
		"p.crt": p.cert, "p.key": p.key, "ok.crt": ok.cert, "ok.key": ok.key,
		"nginx.conf": `http {
  server { listen 8443 ssl proxy_protocol; ssl_certificate /ROOT/p.crt; ssl_certificate_key /ROOT/p.key; }
  server { listen 8444 ssl; ssl_certificate /ROOT/ok.crt; ssl_certificate_key /ROOT/ok.key; } }`,
	})
	conf := root + "/nginx.conf"
	if err := writeFile(conf, strings.ReplaceAll(content(t, conf), "/ROOT", root)); err != nil {
		t.Fatal(err)
	}
	targets, warnings := analyze([]instance{load(t, 100, conf)})
	if len(targets) != 1 || targets[0].Settings[SettingCertificate] != root+"/ok.crt" {
		t.Fatalf("targets %v, want ok.crt alone", targets)
	}
	if !hasWarning(warnings, "p.crt` is not suggested", "PROXY protocol") {
		t.Fatalf("warnings %q", warnings)
	}
}
