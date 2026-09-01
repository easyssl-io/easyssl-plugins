package ops_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

func TestDescribeDeclaresTheReloadCommand(t *testing.T) {
	d := ops.Describe()
	if d.ContractVersion != ops.ContractVersion || d.Name != "generic-cli" {
		t.Fatalf("describe identity = %q %q", d.ContractVersion, d.Name)
	}
	if d.Version == "" {
		t.Fatal("describe reports no version")
	}
	if len(d.Settings) != 1 {
		t.Fatalf("describe declares %d settings, want exactly the reload command", len(d.Settings))
	}
	s := d.Settings[0]
	if s.Key != "reload" || s.Type != ops.SettingTypeCommand || !s.Required {
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
	if s.Label == "" || s.Description == "" {
		t.Fatal("the declaration is what the web console renders; it needs a label and a description")
	}
}

// The default template must succeed while installing nothing: that is what
// lets a Target be created and deployed before anyone writes a real command.
func TestDefaultTemplateSucceedsAndInstallsNothing(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := ops.Install(context.Background(), request(dir, ops.Describe().Settings[0].Default))
	if !res.OK {
		t.Fatalf("the declared default failed: %s", res.Output)
	}
	if !strings.Contains(res.Output, "certificate: ") || !strings.Contains(res.Output, "key: ") {
		t.Fatalf("the default template's output does not name the paths: %s", res.Output)
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

	res := ops.Install(context.Background(), request(dir, script))
	if !res.OK {
		t.Fatalf("install failed: %s", res.Output)
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

// A failed command is a failed Deployment, not a failed Plugin: install
// returns ok:false with everything the command printed, and the process still
// exits 0, which is what the Agent distinguishes.
func TestInstallReportsAFailedCommandWithItsOutput(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := ops.Install(context.Background(), request(dir,
		`echo "about to fail"; echo "on stderr" >&2; exit 3`))
	if res.OK {
		t.Fatal("a command exiting 3 reported ok")
	}
	if !strings.Contains(res.Output, "about to fail") {
		t.Fatalf("output lost what the command printed: %s", res.Output)
	}
	// Combined, because a reload command's diagnostics are as much of the
	// record as its output.
	if !strings.Contains(res.Output, "on stderr") {
		t.Fatalf("output lost the command's stderr: %s", res.Output)
	}
	if !strings.Contains(res.Output, "exited 3") {
		t.Fatalf("output does not say how the command ended: %s", res.Output)
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
	res := ops.Install(context.Background(), request(dir,
		"ls /dont/exist\necho success"))
	if res.OK {
		t.Fatalf("a script whose second line exits 0 hid its first line's failure: %s", res.Output)
	}
	if !strings.Contains(res.Output, "install failed: the reload command exited") {
		t.Fatalf("output does not say the command failed: %s", res.Output)
	}
	// -e ends the script at the failing line, so what follows it never ran.
	if strings.Contains(res.Output, "success") {
		t.Fatalf("the line after the failure still ran: %s", res.Output)
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
	res := ops.Install(context.Background(), request(dir,
		"cp /dont/exist "+filepath.Join(dir, "x")+" && echo reloaded; echo done"))
	if !res.OK {
		t.Fatalf("POSIX -e ended the script on the left of &&, which the description says it does not: %s", res.Output)
	}
	if strings.Contains(res.Output, "reloaded") {
		t.Fatalf("the right side of && ran after its left failed: %s", res.Output)
	}
	if !strings.Contains(res.Output, "done") {
		t.Fatalf("the line after the list did not run: %s", res.Output)
	}
}

// The opt-out is in the script's own text, where the next reader sees it: a
// script that wants last-line semantics says `set +e` on its first line.
func TestInstallLetsAScriptOptOutOfFailingFast(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	res := ops.Install(context.Background(), request(dir,
		"set +e\nls /dont/exist\necho carried on"))
	if !res.OK {
		t.Fatalf("set +e did not restore last-line semantics: %s", res.Output)
	}
	if !strings.Contains(res.Output, "carried on") {
		t.Fatalf("the line after the tolerated failure did not run: %s", res.Output)
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
	res := ops.Install(context.Background(), request(dir, `printf '%s\n' "$0" "$@" > `+record))
	if !res.OK {
		t.Fatalf("install failed: %s", res.Output)
	}
	argv := readFile(t, record)
	if strings.Contains(argv, "KEY") || strings.Contains(argv, "PRIVATE KEY") {
		t.Fatalf("key material reached a command line: %q", argv)
	}
	if strings.Contains(argv, "CERT") {
		t.Fatalf("certificate material reached a command line: %q", argv)
	}
}

// A Deployment whose reload command is missing is refused rather than reported
// as a success that installed nothing.
func TestInstallWithoutACommandFails(t *testing.T) {
	dir := t.TempDir()
	for _, settings := range []map[string]string{nil, {}, {"reload": "   "}} {
		res := ops.Install(context.Background(), ops.InstallRequest{
			ContractVersion: ops.ContractVersion,
			CertificatePem:  testCert, ChainPem: testChain, PrivateKeyPem: testKey,
			WorkDir: dir, Settings: settings,
		})
		if res.OK {
			t.Fatalf("install with settings %v reported ok", settings)
		}
		if !strings.Contains(res.Output, "no reload command") {
			t.Fatalf("output does not say what is missing: %s", res.Output)
		}
	}
}

// Run by hand with no workDir, the Plugin makes its own and removes it, so
// nothing is left behind by someone trying the binary out.
func TestInstallWithoutAWorkDirCleansUpAfterItself(t *testing.T) {
	requirePOSIXShell(t)
	dir := t.TempDir()
	record := filepath.Join(dir, "where.txt")
	res := ops.Install(context.Background(), ops.InstallRequest{
		ContractVersion: ops.ContractVersion,
		CertificatePem:  testCert, ChainPem: testChain, PrivateKeyPem: testKey,
		Settings: map[string]string{"reload": `dirname "$EASYSSL_KEY_PATH" > ` + record},
	})
	if !res.OK {
		t.Fatalf("install failed: %s", res.Output)
	}
	used := strings.TrimSpace(readFile(t, record))
	if used == "" {
		t.Fatal("the command never saw a working directory")
	}
	if _, err := os.Stat(used); !os.IsNotExist(err) {
		t.Fatalf("the self-made working directory %s survived (err=%v)", used, err)
	}
}

func request(workDir, command string) ops.InstallRequest {
	return ops.InstallRequest{
		ContractVersion: ops.ContractVersion,
		CertificatePem:  testCert,
		ChainPem:        testChain,
		PrivateKeyPem:   testKey,
		WorkDir:         workDir,
		Settings:        map[string]string{"reload": command},
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
