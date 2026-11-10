package ops

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// certbotTree is a host whose nginx reads a certbot lineage three ways: an
// absolute path in double quotes, a key in single quotes, and a relative path
// in a file an `include` reaches through a symlink. Copies of the files are
// already where they are to move, as the Agent leaves them.
func certbotTree(t *testing.T) (root string, m material) {
	t.Helper()
	m = issue(t, "ec", "a.example.test")
	root = tree(t, map[string]string{
		"nginx.conf": `http {
    include sites/*.conf;
    server { listen 9001 ssl; ssl_certificate "/ROOT/le/live/a/fullchain.pem"; ssl_certificate_key '/ROOT/le/live/a/privkey.pem'; }
}
`,
		"avail/a.conf": `server {
    listen 9002 ssl;
    ssl_certificate     le/live/a/fullchain.pem;   # relative to nginx.conf
    ssl_certificate_key /ROOT/le/live/a/privkey.pem;
}
`,
		"sites/a.conf":              "->../avail/a.conf",
		"le/archive/a/cert1.pem":    m.cert,
		"le/archive/a/privkey1.pem": m.key,
		"le/live/a/fullchain.pem":   "->../../archive/a/cert1.pem",
		"le/live/a/privkey.pem":     "->../../archive/a/privkey1.pem",
		"easyssl/a/certificate.pem": m.cert,
		"easyssl/a/key.pem":         m.key,
	})
	replaceRoot(t, root, "nginx.conf")
	replaceRoot(t, root, "avail/a.conf")
	if err := os.Chmod(root+"/avail/a.conf", 0o640); err != nil {
		t.Fatal(err)
	}
	return root, m
}

// commandsLogged gives an instance commands that record their order in
// dir/log, the test exiting testExit.
func commandsLogged(in instance, dir string, testExit int) instance {
	log := filepath.Join(dir, "log")
	in.Test = "echo test >> " + log + "; exit " + string(rune('0'+testExit))
	in.Reload = "echo reload >> " + log
	return in
}

// moveOut is the request the Agent sends to move the certbot certificate's
// references to the copies: one move per spelling, and the references
// discovery reported.
func moveOut(t *testing.T, root string, in instance) RelocateRequest {
	t.Helper()
	targets, _ := analyze([]instance{in})
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

// runRelocate runs relocate in English with confirm standing in for the
// check that nginx applied the reload.
func runRelocate(t *testing.T, req RelocateRequest, confirm error, found ...instance) (string, error) {
	t.Helper()
	defer func(f func(instance, reloadMark) error) { confirmReload = f }(confirmReload)
	confirmReload = func(instance, reloadMark) error { return confirm }
	var out bytes.Buffer
	err := relocate(context.Background(), catalog.In("en"), req, found, &out, &out)
	return out.String(), err
}

func TestRelocateRewritesTheConfirmedLines(t *testing.T) {
	root, _ := certbotTree(t)
	conf := root + "/nginx.conf"
	in := commandsLogged(load(t, 100, conf), root, 0)
	req := moveOut(t, root, in)
	if len(req.References) != 4 {
		t.Fatalf("references %+v, want both directives in both files", req.References)
	}
	out, err := runRelocate(t, req, nil, in)
	if err != nil {
		t.Fatalf("relocate: %v\n%s", err, out)
	}
	if got := content(t, conf); !strings.Contains(got, `ssl_certificate "`+root+`/easyssl/a/certificate.pem"; ssl_certificate_key '`+root+`/easyssl/a/key.pem';`) {
		t.Errorf("nginx.conf lost its quoting or was not changed:\n%s", got)
	}
	want := "    ssl_certificate     " + root + "/easyssl/a/certificate.pem;   # relative to nginx.conf\n    ssl_certificate_key " + root + "/easyssl/a/key.pem;\n"
	if got := content(t, root+"/avail/a.conf"); !strings.Contains(got, want) {
		t.Errorf("the included file:\n%s\nwant it to hold:\n%s", got, want)
	}
	if fi, err := os.Lstat(root + "/sites/a.conf"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the include's symlink was replaced by a file")
	}
	if mode(t, root+"/avail/a.conf") != 0o640 {
		t.Errorf("mode %04o, want the file's 0640 kept", mode(t, root+"/avail/a.conf"))
	}
	if got := content(t, root+"/log"); got != "test\nreload\n" {
		t.Errorf("commands ran as %q, want test then reload", got)
	}
	for _, s := range []string{"`" + conf + ":3`: `" + root + "/le/live/a/fullchain.pem` → `" + root + "/easyssl/a/certificate.pem`", "Changed 4 lines"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	// Discovery now finds the copies, named where the certificate was.
	targets, _ := analyze([]instance{load(t, 100, conf)})
	if len(targets) != 1 || targets[0].Settings[SettingCertificate] != root+"/easyssl/a/certificate.pem" ||
		targets[0].Settings[SettingKey] != root+"/easyssl/a/key.pem" || len(targets[0].References) != 4 {
		t.Fatalf("after the move: %+v", targets)
	}
}

// Only the confirmed references change: one the configuration holds and the
// list does not, or the other way round, refuses the whole move.
func TestRelocateRefusesWhatWasNotConfirmed(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	before := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf")
	full := moveOut(t, root, in)

	short := full
	short.References = full.References[1:]
	out, err := runRelocate(t, short, nil, in)
	if err == nil || !strings.Contains(out, "- found, not confirmed: `"+full.References[0].File) {
		t.Errorf("a reference left out: %v\n%s", err, out)
	}
	long := full
	long.References = append(append([]plugincontract.Reference{}, full.References...),
		plugincontract.Reference{Setting: SettingCertificate, File: root + "/nginx.conf", Line: 9, Value: root + "/le/live/a/fullchain.pem"})
	out, err = runRelocate(t, long, nil, in)
	if err == nil || !strings.Contains(out, "- confirmed, not found: `"+root+"/nginx.conf:9`") {
		t.Errorf("a reference too many: %v\n%s", err, out)
	}
	if after := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf"); after != before {
		t.Error("a refused move changed the configuration")
	}
	if _, err := os.Stat(root + "/log"); !os.IsNotExist(err) {
		t.Error("a refused move ran a command")
	}
}

func TestRelocateFailedTestPutsTheFilesBack(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 1)
	before := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf")
	out, err := runRelocate(t, moveOut(t, root, in), nil, in)
	if err == nil || !strings.Contains(out, "exited 1, so nothing was reloaded. The original configuration is back.") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if after := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf"); after != before {
		t.Error("the original configuration was not put back")
	}
	if got := content(t, root+"/log"); got != "test\n" {
		t.Errorf("commands ran as %q, want the test alone", got)
	}
}

// A reload nginx did not apply puts the files back and reloads again, so
// nginx runs the configuration on disk.
func TestRelocateFailedReloadPutsTheFilesBackAndReloads(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	before := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf")
	out, err := runRelocate(t, moveOut(t, root, in), notApplied{line: "bind() to 0.0.0.0:9001 failed"}, in)
	if err == nil || !strings.Contains(out, "Reloading nginx (`pid 100`) failed: nginx did not apply it: bind() to 0.0.0.0:9001 failed. The original configuration is back.") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if after := content(t, root+"/nginx.conf") + content(t, root+"/avail/a.conf"); after != before {
		t.Error("the original configuration was not put back")
	}
	if got := content(t, root+"/log"); got != "test\nreload\nreload\n" {
		t.Errorf("commands ran as %q, want test, reload, and the reload of the original", got)
	}
}

func TestRelocateRefusesBadDestinations(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	before := content(t, root+"/nginx.conf")
	for to, why := range map[string]string{
		"easyssl/a/certificate.pem":          "not an absolute path",
		root + "/easyssl/a/missing.pem":      "no file exists there",
		root + "/easyssl/a":                  "not a regular file",
		root + `/easyssl/a/certificate".pem`: "quote",
	} {
		req := moveOut(t, root, in)
		req.Moves[0].To = to
		if out, err := runRelocate(t, req, nil, in); err == nil || !strings.Contains(out, why) {
			t.Errorf("%s: %v\n%s", to, err, out)
		}
	}
	if content(t, root+"/nginx.conf") != before {
		t.Error("a refused move changed the configuration")
	}
}

// A line edited between discovery and the move is refused, changing nothing.
func TestRelocateRefusesALineEditedSince(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	req := moveOut(t, root, in)
	edited := strings.Replace(content(t, root+"/avail/a.conf"), "le/live/a/fullchain.pem", "le/live/a/cert.pem", 1)
	if err := writeFile(root+"/avail/a.conf", edited); err != nil {
		t.Fatal(err)
	}
	before := content(t, root+"/nginx.conf")
	out, err := runRelocate(t, req, nil, in)
	if err == nil || !strings.Contains(out, "no longer holds `ssl_certificate le/live/a/fullchain.pem`") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
	if content(t, root+"/nginx.conf") != before || content(t, root+"/avail/a.conf") != edited {
		t.Error("a refused move changed a file")
	}
}

func TestRelocateWithNothingToMove(t *testing.T) {
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	out, err := runRelocate(t, RelocateRequest{}, nil, in)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Fatalf("relocate = %v\n%s", err, out)
	}
}

func TestRelocateSpeaksTheHostsLanguage(t *testing.T) {
	t.Setenv("EASYSSL_LANG", "es")
	if hostLanguage() != "es" {
		t.Fatalf("hostLanguage = %q with EASYSSL_LANG=es", hostLanguage())
	}
	t.Setenv("EASYSSL_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "es_PE.UTF-8")
	if hostLanguage() != "es" {
		t.Fatalf("hostLanguage = %q with LANG=es_PE.UTF-8", hostLanguage())
	}
	root, _ := certbotTree(t)
	in := commandsLogged(load(t, 100, root+"/nginx.conf"), root, 0)
	var out bytes.Buffer
	defer func(f func(instance, reloadMark) error) { confirmReload = f }(confirmReload)
	confirmReload = func(instance, reloadMark) error { return nil }
	if err := relocate(context.Background(), catalog.In("es"), moveOut(t, root, in), []instance{in}, &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Se cambiaron 4 líneas") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestLex(t *testing.T) {
	src := `a "b\"c" 'd e'; # f g` + "\n" + `h${i}j \; {k}` + "\n"
	var got []string
	for _, tk := range lex([]byte(src)) {
		got = append(got, tk.value+"|"+src[tk.start:tk.end])
	}
	want := []string{`a|a`, `b"c|"b\"c"`, `d e|'d e'`, `;|;`, `h${i}j|h${i}j`, `\;|\;`, `{|{`, `k|k`, `}|}`}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("lex = %q\nwant  %q", got, want)
	}
	if tk := lex([]byte(src))[4]; tk.line != 2 {
		t.Errorf("line %d, want 2", tk.line)
	}
}
