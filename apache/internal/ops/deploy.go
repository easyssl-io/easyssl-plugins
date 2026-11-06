package ops

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Deploy installs a Certificate at an Apache Target. Before writing anything
// it checks the Target against the running system as discovery would, and
// every certificate and key the reload will load, because a reload that fails
// on any of them makes the master exit while the reload command still exits
// 0. It then writes the full chain and the key without changing anything but
// their content, tests the configuration as the instance, reloads, and checks
// that every place the file is served now serves the new Certificate. Any
// failure after writing puts the previous files back, and a master the
// reload stopped is started again.
//
// There is no response document: the exit status is the answer, and what
// happened is on stdout and stderr, which the Agent records in order.
func Deploy(ctx context.Context, req DeployRequest, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "%s %s · deploy\n", Name, Version())
	for _, k := range []string{SettingCertificate, SettingKey, SettingTest, SettingReload} {
		if strings.TrimSpace(req.Settings[k]) == "" {
			return fmt.Errorf("the %q setting has no value; the Server should not have queued this Deployment", k)
		}
	}
	certPath, err := target(req.Settings[SettingCertificate])
	if err != nil {
		return err
	}
	keyPath, err := target(req.Settings[SettingKey])
	if err != nil {
		return err
	}
	if certPath == keyPath {
		return fmt.Errorf("SSLCertificateFile and SSLCertificateKeyFile are both %s; this Plugin writes the certificate and the key as two files", certPath)
	}
	leaf, err := pemfile.ParseLeaf(req.CertificatePem)
	if err != nil {
		return err
	}
	if pemfile.EncryptedKey([]byte(req.PrivateKeyPem)) {
		return errors.New("the Deployment's private key is encrypted, which Apache could not load without a passphrase")
	}
	if err := pemfile.PairMatches([]byte(req.CertificatePem), []byte(req.PrivateKeyPem)); err != nil {
		return fmt.Errorf("the Deployment's certificate and key do not belong together: %w", err)
	}

	// Step 2: the Target as discovery sees it now.
	masters, err := scanMasters()
	if err != nil {
		return fmt.Errorf("the running Apache instances could not be read: %v", err)
	}
	sv := surveyOf(masters, readConfig)
	for _, w := range sv.warnings {
		fmt.Fprintf(stdout, "note: %s\n", w.In(l10n.English))
	}
	var file *certFile
	for _, f := range sv.files {
		if f.path == certPath {
			file = f
		}
	}
	if file == nil {
		return deployAhead(ctx, req, certPath, keyPath, stdout, stderr)
	}
	if w := sv.warningFor(file); w != nil {
		return fmt.Errorf("the Target no longer passes discovery's checks, so nothing was written: %s", w.In(l10n.English))
	}
	if !sv.suggestable(file) {
		return fmt.Errorf("%s is part of a collision discovery reports (run discovery to see it), so nothing was written", certPath)
	}
	m := file.locs[0].m
	s := sv.cfgs[m]

	// Step 3, the existing key, which discovery already refuses when it is
	// encrypted; checked here too because it is what the reload depends on.
	for _, l := range file.locs {
		if l.keyPath != keyPath {
			return fmt.Errorf("the configuration at %s pairs %s with the key %s, but this Target writes the key to %s, "+
				"so Apache would load the new certificate with the old key. Set SSLCertificateKeyFile to %s", l.where, certPath, l.keyPath, keyPath, l.keyPath)
		}
	}

	// Step 4: every other pair the reload loads.
	if err := preflight(m, s, certPath); err != nil {
		return fmt.Errorf("nothing was written, because the reload would fail on a file this Deployment does not touch: %w", err)
	}

	// Step 5: the key-type guard.
	newAlg := leaf.PublicKeyAlgorithm.String()
	for _, l := range file.locs {
		if l.alg == newAlg {
			continue
		}
		for _, sib := range l.siblings {
			if ci, err := readCert(sib); err == nil && ci.alg() == newAlg {
				return fmt.Errorf("%s holds an %s certificate, and the place at %s also loads %s, which is %s already; "+
					"installing an %s Certificate here would leave Apache with two %s certificates and no %s one. "+
					"Request an %s Certificate for this Target instead", certPath, l.alg, l.where, sib, newAlg, newAlg, newAlg, l.alg, l.alg)
			}
		}
	}

	// Steps 6 to 8.
	fullchain, err := pemfile.JoinPEM(req.CertificatePem, req.ChainPem)
	if err != nil {
		return err
	}
	written, err := hostfile.WritePair(WriteFileFlag, certPath, keyPath, []byte(fullchain), []byte(req.PrivateKeyPem), stdout, stderr)
	if err != nil {
		return err
	}

	// Step 9.
	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingTest])
	out, err := runSetting(ctx, req.Settings[SettingTest], m.runEnv(), m.Cred)
	io.WriteString(stdout, out)
	if err != nil {
		written.Restore(stdout, stderr)
		return fmt.Errorf("the test command %s, so nothing was reloaded and the previous files were put back", describeExit(err))
	}

	// Steps 10 to 12. m was read before the reload, so it is also what a
	// restart outside any supervisor reproduces.
	eps := endpointsFor(file, newAlg)
	markErrorLog(m)

	if err := reload(ctx, m, req.Settings[SettingReload], stdout); err != nil {
		written.Restore(stdout, stderr)
		if !m.alive() {
			return recoverMaster(ctx, m, s, stdout, stderr, fmt.Errorf("the reload command %s", describeExit(err)))
		}
		return fmt.Errorf("%v; the previous files were put back", err)
	}

	// Step 12.
	served, err := verify(m, eps, leaf.Raw, stdout)
	if err == nil {
		fmt.Fprintln(stdout, served)
		return nil
	}
	written.Restore(stdout, stderr)
	if !m.alive() {
		return recoverMaster(ctx, m, s, stdout, stderr, err)
	}
	if rerr := reload(ctx, m, req.Settings[SettingReload], stdout); rerr != nil {
		return fmt.Errorf("%v; the previous files were put back, and reloading them failed too: %v", err, rerr)
	}
	return fmt.Errorf("%v; the previous files were put back and Apache was reloaded with them", err)
}

// deployAhead installs a Certificate at a path no running Apache loads: a
// Target configured before the configuration that uses it. There is nothing
// to check it against, so it is written, tested and reloaded as the settings
// say, as root, and what Apache serves is not checked.
func deployAhead(ctx context.Context, req DeployRequest, certPath, keyPath string, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "no running Apache loads %s, so it is installed without the checks against a running instance\n", certPath)
	for _, p := range []string{certPath, keyPath} {
		if probs := pathProblems(p); len(probs) > 0 {
			return errors.New(probs[0](catalog.In(l10n.English)))
		}
	}
	fullchain, err := pemfile.JoinPEM(req.CertificatePem, req.ChainPem)
	if err != nil {
		return err
	}
	written, err := hostfile.WritePair(WriteFileFlag, certPath, keyPath, []byte(fullchain), []byte(req.PrivateKeyPem), stdout, stderr)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingTest])
	out, err := runSetting(ctx, req.Settings[SettingTest], nil, cred{})
	io.WriteString(stdout, out)
	if err != nil {
		written.Restore(stdout, stderr)
		return fmt.Errorf("the test command %s, so nothing was reloaded and the previous files were put back", describeExit(err))
	}
	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingReload])
	out, err = runSetting(ctx, req.Settings[SettingReload], nil, cred{})
	io.WriteString(stdout, out)
	if err != nil {
		return fmt.Errorf("the reload command %s; the new files stay in place", describeExit(err))
	}
	fmt.Fprintln(stdout, "Installed and reloaded. No running Apache loaded this file before, so what it serves was not checked.")
	return nil
}

// scanMasters is scan, replaced in tests, where no Apache runs.
var scanMasters = scan

// target is the file a setting names, followed through symlinks when it
// exists: replacing a symlink with a regular file would cut whatever else it
// links (a certbot `live/` directory, a shared snippet) away from the file.
func target(setting string) (string, error) {
	if !filepath.IsAbs(setting) {
		return "", fmt.Errorf("%q is not an absolute path; a discovered Target names one, and a Target created by hand must too", setting)
	}
	real, err := filepath.EvalSymlinks(setting)
	if errors.Is(err, os.ErrNotExist) {
		return filepath.Clean(setting), nil
	}
	return real, err
}

// pair is a certificate file and the key mod_ssl pairs with it, by position.
type pair struct {
	cert, key string
	at        string // the SSLCertificateFile's file:line
}

// loadedPairs is every certificate and key m loads: those of each virtual host
// with SSLEngine on, and the server-level ones when the main server serves TLS
// or such a virtual host has none of its own and inherits them. A
// certificate with no key of its own carries its key inside.
func loadedPairs(m *master, s *serverCfg) []pair {
	var out []pair
	add := func(certs, keys []directive) {
		for i, c := range certs {
			p := pair{cert: resolveIn(m.ServerRoot, c.args[0]), at: fmt.Sprintf("%s:%d", c.file, c.line)}
			p.key = p.cert
			if i < len(keys) {
				p.key = resolveIn(m.ServerRoot, keys[i].args[0])
			}
			out = append(out, p)
		}
	}
	serverLevel := s.engineOn(nil)
	for _, v := range s.vhosts {
		if !s.engineOn(v) {
			continue
		}
		if len(v.certs) == 0 {
			serverLevel = true
			continue
		}
		add(v.certs, v.keys)
	}
	if serverLevel {
		add(s.certs, s.keys)
	}
	return out
}

// preflight checks every certificate and key pair m loads, other than the
// Target's own, the way mod_ssl will on the reload: each file readable by the
// master, each key matching the certificate at its position, and an encrypted
// key only when the master already holds it decrypted, which mod_ssl keeps
// across a reload only for a key file unchanged since it was loaded. httpd's
// configuration test checks none of this, and any one of them makes the
// master exit on the reload.
func preflight(m *master, s *serverCfg, skip string) error {
	loaded, err := os.Stat(m.PidFile)
	if err != nil {
		return fmt.Errorf("the PidFile %s: %w", m.PidFile, err)
	}
	for _, p := range loadedPairs(m, s) {
		if p.cert == skip {
			continue
		}
		for _, f := range []string{p.cert, p.key} {
			if !readableBy(m.Cred, f) {
				return fmt.Errorf("pid %d runs as uid %d and cannot read %s (%s)", m.PID, m.Cred.UID, f, p.at)
			}
		}
		cb, err1 := os.ReadFile(p.cert)
		kb, err2 := os.ReadFile(p.key)
		if err1 != nil || err2 != nil {
			continue
		}
		if pemfile.EncryptedKey(kb) {
			if fi, err := os.Stat(p.key); err == nil && fi.ModTime().After(loaded.ModTime().Add(clockSlack)) {
				return fmt.Errorf("%s is encrypted and changed since pid %d last loaded its configuration, so the reload would need its passphrase", p.key, m.PID)
			}
			continue
		}
		der, err := pemfile.LeafDER(cb)
		if err != nil {
			continue
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			continue // a certificate this Plugin cannot read is Apache's to judge
		}
		key, err := pemfile.ParseKey(kb)
		if err != nil {
			continue
		}
		if !pemfile.KeyMatches(leaf, key) {
			return fmt.Errorf("the key %s does not match the certificate %s (%s), and mod_ssl refuses that pair on the reload (AH02565)", p.key, p.cert, p.at)
		}
	}
	return nil
}

// runSetting runs a test or reload setting as one `/bin/sh -e -c` script, so a
// multi-line command stops at its first failing line. env nil is this
// process's environment; a non-root c runs it as that user.
func runSetting(ctx context.Context, script string, env []string, c cred) (string, error) {
	var sc *syscall.Credential
	if !c.IsRoot() {
		sc = c.Sys()
	}
	return runCmd(sc, env, "/bin/sh", "-e", "-c", script)
}

// reload runs the reload setting with the instance's environment. A master no
// supervisor manages is reloaded as the user it runs as, after the guard:
// `httpd -k graceful` reads the whole configuration before it signals, so
// run as root against an ordinary user's master it would load that user's
// modules, and honor their LD_LIBRARY_PATH, as root. That user can signal its
// own master, so nothing needs more. A supervisor's reload stays root's: the
// supervisor runs the service's own reload, under the service's settings.
func reload(ctx context.Context, m *master, script string, stdout io.Writer) error {
	as := cred{}
	if m.Graceful {
		if err := m.guard(); err != nil {
			return fmt.Errorf("the reload was not run: %v", err)
		}
		as = m.Cred
	}
	fmt.Fprintf(stdout, "$ %s\n", script)
	out, err := runSetting(ctx, script, m.runEnv(), as)
	io.WriteString(stdout, out)
	if err != nil {
		return fmt.Errorf("the reload command %s", describeExit(err))
	}
	return nil
}

// describeExit words a command's failure for the run's last line.
func describeExit(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ProcessState != nil && ee.ProcessState.ExitCode() >= 0 {
			return fmt.Sprintf("exited with status %d", ee.ProcessState.ExitCode())
		}
		return "was killed by a signal"
	}
	return "could not be run: " + err.Error()
}
