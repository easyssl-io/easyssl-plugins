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

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// liveNote is the last line of a successful run that found no place to check
// what nginx serves (endpoints.go says which places it trusts). It is there
// because the success then means less than it seems to: `nginx -s reload`, and `systemctl
// reload` which runs it, returns once the signal is sent, and the master
// applies the new configuration afterwards. If applying any part of it fails,
// most often a `listen` it cannot bind in a file unrelated to this Target,
// the master discards the whole reload, keeps serving the previous
// configuration and logs `[emerg]` after this command has already exited 0.
const liveNote = "Installed and reloaded. nginx applies a reload after this command returns and keeps its " +
	"previous configuration if applying it fails, so this does not confirm the new Certificate is being served."

// Deploy installs a Certificate at an nginx Target: it writes the full chain
// and the key where the Target's settings say, with nothing but their content
// changed, runs the test command, and reloads only when that passes. It then
// asks every place the file is served (endpoints.go) which certificate it
// presents, because nginx applies a reload after the command returns and
// keeps its previous configuration when applying it fails. When the test
// fails, or the new Certificate is not served, the files it replaced are put
// back, so a later reload for any other reason does not pick up a pair nginx
// refused, and after a reload nginx is reloaded with them again.
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
		return fmt.Errorf("ssl_certificate and ssl_certificate_key are both %s; nginx reads a certificate and a key, and one file holding both is not what this Plugin writes", certPath)
	}
	leaf, err := pemfile.ParseLeaf(req.CertificatePem)
	if err != nil {
		return err
	}
	if pemfile.EncryptedKey([]byte(req.PrivateKeyPem)) {
		return errors.New("the Deployment's private key is encrypted, which nginx could not load without its ssl_password_file")
	}
	if err := pemfile.PairMatches([]byte(req.CertificatePem), []byte(req.PrivateKeyPem)); err != nil {
		return fmt.Errorf("the Deployment's certificate and key do not belong together: %w", err)
	}
	for _, p := range []string{certPath, keyPath} {
		if probs := pathProblems(p); len(probs) > 0 {
			return fmt.Errorf("nothing was written: %s", probs[0].In(l10n.English))
		}
	}
	live := servingOf(certPath)
	serving := live.blocks
	if err := checkPairing(certPath, keyPath, serving); err != nil {
		return err
	}
	if err := checkDual(certPath, leaf.PublicKeyAlgorithm, func(string) []block { return serving }); err != nil {
		return err
	}
	eps := endpointsFor(live.servers, certPath, leaf.PublicKeyAlgorithm.String())

	fullchain := pemfile.JoinPEM(req.CertificatePem, req.ChainPem)
	written, err := hostfile.WritePair(OpWriteFile, certPath, keyPath, []byte(fullchain), []byte(req.PrivateKeyPem), stdout, stderr)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingTest])
	if err := runScript(ctx, req.Settings[SettingTest], stdout, stderr); err != nil {
		written.Restore(stdout, stderr)
		return fmt.Errorf("the test command %s, so nothing was reloaded and the previous files were put back", describeExit(err))
	}
	marks := logMarks(live.logs)
	if err := reload(ctx, req, stdout, stderr); err != nil {
		return fmt.Errorf("%v; the new files stay in place, and nginx keeps serving what it last loaded", err)
	}
	if len(live.pids) == 0 || len(eps) == 0 {
		fmt.Fprintln(stdout, liveNote)
		return nil
	}
	served, err := tlscheck.Verify(live.alive, eps, leaf.Raw, stdout)
	if err == nil {
		fmt.Fprintln(stdout, served)
		return nil
	}
	emerg := emergSince(marks)
	for _, l := range emerg {
		fmt.Fprintf(stdout, "nginx logged: %s\n", l)
	}
	written.Restore(stdout, stderr)
	if errors.Is(err, tlscheck.ErrGone) {
		return fmt.Errorf("%v after the reload; the previous files were put back, and nginx has to be started again", err)
	}
	if rerr := reload(ctx, req, stdout, stderr); rerr != nil {
		return fmt.Errorf("%v; the previous files were put back, and reloading them failed too: %v", err, rerr)
	}
	why := "most likely because applying the reload failed, which its error log says"
	if len(emerg) > 0 {
		why = "because applying the reload failed: " + emerg[0]
	}
	return fmt.Errorf("%v. nginx kept its previous configuration %s; the previous files were put back and nginx was reloaded with them", err, why)
}

// reload runs the reload setting.
func reload(ctx context.Context, req DeployRequest, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingReload])
	if err := runScript(ctx, req.Settings[SettingReload], stdout, stderr); err != nil {
		return fmt.Errorf("the reload command %s", describeExit(err))
	}
	return nil
}

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

// checkPairing refuses a Target whose key file is not the one nginx pairs its
// certificate with. The key would land where nothing reads it, and the
// certificate beside whatever key nginx does read. `nginx -t` catches that
// only when the two keys share an algorithm: with an RSA certificate and an
// ECDSA key, OpenSSL files each in its own slot, the test passes, and the
// server is left with an RSA certificate and no RSA key. Found on a
// sysvinit test host, where exactly that Deployment succeeded.
func checkPairing(certPath, keyPath string, serving []block) error {
	for _, b := range serving {
		for _, r := range pair(b) {
			if r.Resolved == certPath && r.KeyResolved != "" && r.KeyResolved != keyPath {
				return fmt.Errorf("the configuration at %s:%d pairs %s with the key %s, but this Target writes the key to %s, "+
					"so nginx would serve the new certificate with the old key. Set ssl_certificate_key to %s", r.File, r.KeyLine, certPath, r.KeyResolved, keyPath, r.KeyResolved)
			}
		}
	}
	return nil
}

// checkDual refuses to put a Certificate of one algorithm where the server
// block already loads another Certificate of that algorithm, which is what
// replacing the RSA half of a dual RSA and ECDSA pair with an ECDSA
// Certificate would do. OpenSSL keeps one slot per algorithm, so nginx would
// load both files into one slot, the later one winning, and the other half of
// the pair would stop being served with nothing reporting it.
//
// Replacing a file with a Certificate of another algorithm is otherwise fine,
// as is a path no running nginx loads yet: a Target configured in advance.
func checkDual(path string, alg x509.PublicKeyAlgorithm, serving func(string) []block) error {
	for _, b := range serving(path) {
		var old x509.PublicKeyAlgorithm
		var others []string
		for _, c := range b.certs {
			if c.resolved == path {
				old = certificateAlgorithm(c.resolved)
			} else if certificateAlgorithm(c.resolved) == alg {
				others = append(others, c.resolved)
			}
		}
		if old != x509.UnknownPublicKeyAlgorithm && old != alg && len(others) > 0 {
			return fmt.Errorf("%s holds an %s certificate, and the block at %s also loads %s, which is %s already; "+
				"installing an %s Certificate here would give nginx two %s certificates and no %s one. "+
				"Request an %s Certificate for this Target instead", path, old, b.file, strings.Join(others, ", "), alg, alg, alg, old, old)
		}
	}
	return nil
}

// serving is what the running nginx masters do with a certificate file: the
// configuration blocks that load it, for the checks before writing, and the
// masters and their server blocks, for checking what is served after the
// reload.
type serving struct {
	blocks  []block
	pids    []int
	exes    []string
	logs    []string
	servers []nginxServer
}

// servingOf reads every running master that loads path. Empty when discovery
// cannot run, which leaves the checks nothing to refuse on and the reload
// nothing to check: a Target configured ahead of the configuration that uses
// it.
func servingOf(path string) serving {
	var out serving
	found, err := scan()
	if err != nil {
		return out
	}
	for _, in := range found {
		if in.CertsErr != nil {
			continue
		}
		blocks, _ := blocksOf(in.ConfigPath)
		loads := false
		for _, b := range blocks {
			for _, c := range b.certs {
				if c.resolved == path {
					out.blocks = append(out.blocks, b)
					loads = true
					break
				}
			}
		}
		if !loads {
			continue
		}
		out.pids = append(out.pids, in.PID)
		out.exes = append(out.exes, in.Exe)
		if l := errorLogOf(in.Exe, in.ConfigPath); l != "" {
			out.logs = append(out.logs, l)
		}
		if servers, err := serversOf(in.ConfigPath); err == nil {
			out.servers = append(out.servers, servers...)
		}
	}
	return out
}

// alive reports every master that loads the file still running the binary it
// ran.
func (s serving) alive() bool {
	for i, pid := range s.pids {
		if exeOf(pid) != s.exes[i] {
			return false
		}
	}
	return true
}

// runScript runs a setting as one `/bin/sh -e -c` script, so a multi-line
// command stops at its first failing line, with its output on the Plugin's
// own streams.
func runScript(ctx context.Context, script string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-e", "-c", script)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

func describeExit(err error) string {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Sprintf("exited %d", exit.ExitCode())
	}
	return fmt.Sprintf("could not be run: %v", err)
}
