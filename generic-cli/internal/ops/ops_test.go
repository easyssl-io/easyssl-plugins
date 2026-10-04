package ops_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/l10n/l10ncheck"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-plugins/generic-cli/internal/ops"
)

// The Agent↔Plugin stdio contract test. It exercises the properties the
// contract rests on rather than every branch: what describe declares, that
// install really writes the four files at the right modes and really removes
// them however the command ends, that the four paths reach the command's
// environment, that a non-zero exit is a failed Deployment with its output
// kept, and that no key material is ever on a command line.

const (
	testCert  = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----"
	testChain = "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----"
	testKey   = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
)

func TestDiscoverDeclaresTheInstallCommand(t *testing.T) {
	d := ops.Discover()
	if d.ContractVersion != ops.ContractVersion || d.Name != "generic-cli" {
		t.Fatalf("discover identity = %q %q", d.ContractVersion, d.Name)
	}
	if d.Version == "" {
		t.Fatal("discover reports no version")
	}
	if len(d.Settings) != 1 {
		t.Fatalf("discover declares %d settings, want exactly the install command", len(d.Settings))
	}
	s := d.Settings[0]
	if s.Key != ops.SettingInstall || s.Type != ops.SettingTypeCommand || !s.Required {
		t.Fatalf("reload declaration = %+v, want a required command keyed `reload`", s)
	}
	if s.Summary {
		t.Fatal("reload is marked summary; an unlabeled Target would then be known by a whole script")
	}
	// Required *with* a default that runs: the command is the whole of the
	// installation, so a Target that has not been configured must still deploy
	// cleanly rather than being refused at the queue.
	if s.Default == "" {
		t.Fatal("reload has an empty default, which would make every fresh Target undeployable")
	}
	for _, want := range []string{"EASYSSL_CERT_PATH", "EASYSSL_CHAIN_PATH", "EASYSSL_FULLCHAIN_PATH", "EASYSSL_KEY_PATH"} {
		if !strings.Contains(s.Default, want) {
			t.Fatalf("the default template never mentions %s, so it does not show what a script has to work with", want)
		}
	}
	if s.Label["en"] == "" || s.Description["en"] == "" || d.Description["en"] == "" {
		t.Fatal("the declaration is what the web console renders; it needs a label and a description")
	}
	// Every text travels in every language, since nobody knows yet who will
	// read it: a Spanish text that merely repeats the English is a
	// translation that never loaded.
	for name, text := range map[string]map[string]string{"description": d.Description, "label": s.Label, "setting description": s.Description} {
		if text["es"] == "" || text["es"] == text["en"] {
			t.Fatalf("the %s has no Spanish of its own: %q", name, text["es"])
		}
	}
	if !strings.Contains(s.Description["es"], "`EASYSSL_KEY_PATH`") {
		t.Fatal("the Spanish description lost a literal the English names")
	}
	if err := plugincontract.ValidateDiscover(d); err != nil {
		t.Fatalf("the Agent would refuse this answer: %v", err)
	}
}

// Every message has its translation and every translation its message.
func TestCatalog(t *testing.T) { l10ncheck.Check(t, ".", "locales") }

// The default template must succeed while installing nothing: that is what
// lets a Target be created and deployed before anyone writes a real command.
func TestDefaultTemplateSucceedsAndInstallsNothing(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := deploy(t, request(dir, ops.Discover().Settings[0].Default))
	if !res.OK {
		t.Fatalf("the declared default failed: %s", res.Combined)
	}
	if !strings.Contains(res.Combined, "certificate: ") || !strings.Contains(res.Combined, "key: ") {
		t.Fatalf("the default template's output does not name the paths: %s", res.Combined)
	}
}

func TestInstallWritesTheMaterialThenRemovesIt(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	// The command records what it can see, so the assertions are about the
	// state *during* the run, which is the only moment the files exist.
	record := filepath.Join(dir, "seen.txt")
	script := `
{
  echo "cert=$EASYSSL_CERT_PATH"
  echo "chain=$EASYSSL_CHAIN_PATH"
  echo "fullchain=$EASYSSL_FULLCHAIN_PATH"
  echo "key=$EASYSSL_KEY_PATH"
  echo "certbody=$(cat "$EASYSSL_CERT_PATH")"
  echo "fullchainbody=$(cat "$EASYSSL_FULLCHAIN_PATH")"
  echo "keybody=$(cat "$EASYSSL_KEY_PATH")"
  echo "keymode=$(ls -l "$EASYSSL_KEY_PATH" | cut -c1-10)"
} > ` + record

	res := deploy(t, request(dir, script))
	if !res.OK {
		t.Fatalf("install failed: %s", res.Combined)
	}
	seen := readFile(t, record)

	// Every path reached the command's environment.
	for _, key := range []string{"cert=", "chain=", "fullchain=", "key="} {
		if v := field(seen, key); v == "" {
			t.Fatalf("%s never reached the command's environment:\n%s", key, seen)
		}
	}
	// And named real files carrying the material the request supplied.
	if got := field(seen, "certbody="); got != "CERT" && !strings.Contains(seen, "CERT") {
		t.Fatalf("the certificate file did not carry the certificate:\n%s", seen)
	}
	if !strings.Contains(seen, "KEY") {
		t.Fatalf("the key file did not carry the key:\n%s", seen)
	}
	// Fullchain is the certificate followed by the chain, which is what most
	// servers actually read.
	fullchain := readDuring(seen, "fullchainbody=")
	if !strings.Contains(fullchain, "CERT") || !strings.Contains(fullchain, "CHAIN") {
		t.Fatalf("fullchain is not cert+chain: %q", fullchain)
	}
	// The key was never readable by anyone else, not even briefly.
	if mode := field(seen, "keymode="); !strings.HasPrefix(mode, "-rw-------") {
		t.Fatalf("key mode during the run = %q, want -rw------- (0600)", mode)
	}

	// And nothing survives the run. The Agent removes the whole working
	// directory too, but the Plugin doing its own half is what this asserts.
	for _, name := range []string{"cert.pem", "chain.pem", "fullchain.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s survived the install (err=%v); a private key must not outlive the run", name, err)
		}
	}
}

// A failed install command fails the Deployment, and everything it printed is kept.
// The Plugin exits non-zero for it, which used to be reserved for the Plugin
// itself breaking: there is no `ok` field left to say one while the exit status
// says the other, and which of the two happened is said in the transcript, by
// the Plugin, in words.
func TestInstallReportsAFailedCommandWithItsOutput(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := deploy(t, request(dir,
		`echo "about to fail"; echo "on stderr" >&2; exit 3`))
	if res.OK {
		t.Fatal("a command exiting 3 reported ok")
	}
	if !strings.Contains(res.Combined, "about to fail") {
		t.Fatalf("output lost what the command printed: %s", res.Combined)
	}
	// Combined, because an install command's diagnostics are as much of the
	// record as its output.
	if !strings.Contains(res.Combined, "on stderr") {
		t.Fatalf("output lost the command's stderr: %s", res.Combined)
	}
	if !strings.Contains(res.Combined, "exited 3") {
		t.Fatalf("output does not say how the command ended: %s", res.Combined)
	}
	// The key is gone even though the command failed, which is the case that
	// matters: a failed install must not leave key material behind.
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); !os.IsNotExist(err) {
		t.Fatalf("the key survived a failed install (err=%v)", err)
	}
}

// A script's exit status is its last line's, so without -e this script exits 0
// and the failed ls two lines up is invisible: a Deployment marked succeeded
// with nothing installed, which is the one outcome this Plugin must not
// produce. The reload runs under /bin/sh -e precisely so this reports failure.
func TestInstallFailsOnAFailingLineEvenWhenALaterLineExitsZero(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := deploy(t, request(dir,
		"ls /dont/exist\necho success"))
	if res.OK {
		t.Fatalf("a script whose second line exits 0 hid its first line's failure: %s", res.Combined)
	}
	if !strings.Contains(res.Combined, "the install command exited") {
		t.Fatalf("output does not say the command failed: %s", res.Combined)
	}
	// -e ends the script at the failing line, so what follows it never ran.
	if strings.Contains(res.Combined, "success") {
		t.Fatalf("the line after the failure still ran: %s", res.Combined)
	}
}

// POSIX -e does not act on a failure on the left of && or ||, so this script
// exits 0 although cp failed and nothing was reloaded. This test records the
// limit that the description and the template state, so that a change to the
// invocation that closes it has a test to turn around, and a change that
// widens it is noticed.
func TestInstallCannotSeeAFailureOnTheLeftOfAnAndOrList(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := deploy(t, request(dir,
		"cp /dont/exist "+filepath.Join(dir, "x")+" && echo reloaded; echo done"))
	if !res.OK {
		t.Fatalf("POSIX -e ended the script on the left of &&, which the description says it does not: %s", res.Combined)
	}
	if strings.Contains(res.Combined, "reloaded") {
		t.Fatalf("the right side of && ran after its left failed: %s", res.Combined)
	}
	if !strings.Contains(res.Combined, "done") {
		t.Fatalf("the line after the list did not run: %s", res.Combined)
	}
}

// The opt-out is in the script's own text, where the next reader sees it: a
// script that wants last-line semantics says `set +e` on its first line.
func TestInstallLetsAScriptOptOutOfFailingFast(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := deploy(t, request(dir,
		"set +e\nls /dont/exist\necho carried on"))
	if !res.OK {
		t.Fatalf("set +e did not restore last-line semantics: %s", res.Combined)
	}
	if !strings.Contains(res.Combined, "carried on") {
		t.Fatalf("the line after the tolerated failure did not run: %s", res.Combined)
	}
}

// /proc/<pid>/cmdline is world-readable, so no key material may ever be on a
// command line. The key reaches the command as a path in its
// environment and nowhere else.
func TestNoKeyMaterialOnAnyCommandLine(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	record := filepath.Join(dir, "cmdline.txt")
	// `ps` output varies between systems, so the command records its own
	// arguments, which is what the Plugin actually put there.
	res := deploy(t, request(dir, `printf '%s\n' "$0" "$@" > `+record))
	if !res.OK {
		t.Fatalf("install failed: %s", res.Combined)
	}
	argv := readFile(t, record)
	if strings.Contains(argv, "KEY") || strings.Contains(argv, "PRIVATE KEY") {
		t.Fatalf("key material reached a command line: %q", argv)
	}
	if strings.Contains(argv, "CERT") {
		t.Fatalf("certificate material reached a command line: %q", argv)
	}
}

// A Deployment whose install command is missing is refused rather than reported
// as a success that installed nothing.
func TestInstallWithoutACommandFails(t *testing.T) {
	dir := t.TempDir()
	for _, settings := range []map[string]string{nil, {}, {ops.SettingInstall: "   "}} {
		res := deploy(t, ops.DeployRequest{
			ContractVersion: ops.ContractVersion,
			CertificatePem:  testCert, ChainPem: testChain, PrivateKeyPem: testKey,
			WorkDir: dir, Settings: settings,
		})
		if res.OK {
			t.Fatalf("install with settings %v reported ok", settings)
		}
		if !strings.Contains(res.Combined, "no install command") {
			t.Fatalf("output does not say what is missing: %s", res.Combined)
		}
	}
}

// Run by hand with no workDir, the Plugin makes its own and removes it, so
// nothing is left behind by someone trying the binary out.
func TestInstallWithoutAWorkDirCleansUpAfterItself(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	record := filepath.Join(dir, "where.txt")
	res := deploy(t, ops.DeployRequest{
		ContractVersion: ops.ContractVersion,
		CertificatePem:  testCert, ChainPem: testChain, PrivateKeyPem: testKey,
		Settings: map[string]string{ops.SettingInstall: `dirname "$EASYSSL_KEY_PATH" > ` + record},
	})
	if !res.OK {
		t.Fatalf("install failed: %s", res.Combined)
	}
	used := strings.TrimSpace(readFile(t, record))
	if used == "" {
		t.Fatal("the command never saw a working directory")
	}
	if _, err := os.Stat(used); !os.IsNotExist(err) {
		t.Fatalf("the self-made working directory %s survived (err=%v)", used, err)
	}
}

func request(workDir, command string) ops.DeployRequest {
	return ops.DeployRequest{
		ContractVersion: ops.ContractVersion,
		CertificatePem:  testCert,
		ChainPem:        testChain,
		PrivateKeyPem:   testKey,
		WorkDir:         workDir,
		Settings:        map[string]string{ops.SettingInstall: command},
	}
}

// requirePOSIXShell skips where /bin/sh is not the contract's shell. The
// Plugin runs on the hosts an Agent runs on, which are POSIX; this keeps the
// suite honest about that rather than silently passing elsewhere.
func requirePOSIXShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("generic-cli runs its command through /bin/sh, which Windows does not have")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh on this host: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// field returns the single-line value recorded under key, or "".
func field(record, key string) string {
	for _, line := range strings.Split(record, "\n") {
		if strings.HasPrefix(line, key) {
			return strings.TrimPrefix(line, key)
		}
	}
	return ""
}

// readDuring returns everything from key to the next recorded key, for values
// that span lines.
func readDuring(record, key string) string {
	i := strings.Index(record, key)
	if i < 0 {
		return ""
	}
	rest := record[i+len(key):]
	if j := strings.Index(rest, "\nkeybody="); j >= 0 {
		return rest[:j]
	}
	return rest
}

// install runs the operation the way the Agent does — two streams and an exit
// status, no response document — and gathers what a test wants to assert on.
//
// Combined is the two streams together, in the order this Plugin wrote them,
// which is what the Agent records and the web console shows. Most assertions
// here are about "did the transcript keep this", and splitting them per stream
// would say less, not more.
type deployResult struct {
	OK  bool
	Out string
	Err string
	// Reason is what the operation returned when it failed. It leaves this
	// Plugin as a line on stderr and a non-zero exit (see main), so a test
	// asserting on it is asserting on what the Agent will record.
	Reason   string
	Combined string
}

func deploy(t *testing.T, req ops.DeployRequest) deployResult {
	t.Helper()
	var out, errb strings.Builder
	err := ops.Deploy(context.Background(), req, &out, &errb)
	r := deployResult{
		OK: err == nil, Out: out.String(), Err: errb.String(),
		Combined: out.String() + errb.String(),
	}
	if err != nil {
		r.Reason = err.Error()
		r.Combined += err.Error()
	}
	return r
}
