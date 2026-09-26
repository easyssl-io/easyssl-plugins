package ops

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// defaultMode is a new file's mode, when there is no file being replaced to
// copy one from. The Certificate file is public, but nginx's master reads both
// as root, so the stricter mode costs nothing and one rule is easier to trust.
const defaultMode os.FileMode = 0o600

// liveNote is the last line of a successful run. It is there because the
// success means less than it seems to: `nginx -s reload`, and `systemctl
// reload` which runs it, returns once the signal is sent, and the master
// applies the new configuration afterwards. If applying any part of it fails,
// most often a `listen` it cannot bind in a file unrelated to this Target,
// the master discards the whole reload, keeps serving the previous
// configuration and logs `[emerg]` after this command has already exited 0.
const liveNote = "Installed and reloaded. nginx applies a reload after this command returns and keeps its " +
	"previous configuration if applying it fails, so this does not confirm the new Certificate is being served."

// Deploy installs a Certificate at an nginx Target: it writes the full chain
// and the key where the Target's settings say, runs the test command, and
// reloads only when that passes. When the test fails, the files it replaced
// are put back, so a later reload for any other reason does not pick up a
// pair nginx refused.
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
	leaf, err := parseLeaf(req.CertificatePem)
	if err != nil {
		return err
	}
	if err := checkDual(certPath, leaf.PublicKeyAlgorithm, blocksServing); err != nil {
		return err
	}

	fullchain := joinPEM(req.CertificatePem, req.ChainPem)
	certOld, err := write(certPath, []byte(fullchain), stdout)
	if err != nil {
		return err
	}
	keyOld, err := write(keyPath, []byte(req.PrivateKeyPem), stdout)
	if err != nil {
		restore(certPath, certOld, stdout, stderr)
		return err
	}

	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingTest])
	if err := runScript(ctx, req.Settings[SettingTest], stdout, stderr); err != nil {
		restore(certPath, certOld, stdout, stderr)
		restore(keyPath, keyOld, stdout, stderr)
		return fmt.Errorf("the test command %s, so nothing was reloaded and the previous files were put back", describeExit(err))
	}
	fmt.Fprintf(stdout, "$ %s\n", req.Settings[SettingReload])
	if err := runScript(ctx, req.Settings[SettingReload], stdout, stderr); err != nil {
		return fmt.Errorf("the reload command %s; the new files stay in place, and nginx keeps serving what it last loaded", describeExit(err))
	}
	fmt.Fprintln(stdout, liveNote)
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

func parseLeaf(certificatePEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the Deployment carries no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
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
			return fmt.Errorf("%s holds a %s certificate, and the block at %s also loads %s, which is %s already; "+
				"installing an %s Certificate here would give nginx two %s certificates and no %s one. "+
				"Request an %s Certificate for this Target instead", path, old, b.file, strings.Join(others, ", "), alg, alg, alg, old, old)
		}
	}
	return nil
}

// blocksServing is every configuration block of every running nginx master
// that loads path. Empty when discovery cannot run, which leaves checkDual
// nothing to refuse on.
func blocksServing(path string) []block {
	found, err := scan()
	if err != nil {
		return nil
	}
	var out []block
	for _, in := range found {
		if in.CertsErr != nil {
			continue
		}
		blocks, _ := blocksOf(in.ConfigPath)
		for _, b := range blocks {
			for _, c := range b.certs {
				if c.resolved == path {
					out = append(out, b)
					break
				}
			}
		}
	}
	return out
}

// previous is what a write replaced, for restore: nil data when there was
// no file.
type previous struct {
	data []byte
	info os.FileInfo
}

// write puts data at path so a reader sees either the old file or the new
// one, never part of either, and returns what it replaced.
//
// The temporary file is created in the destination directory, so the rename
// is atomic, at 0600 so it is never readable by others on the way. It then
// takes the replaced file's mode, owner and group, and its SELinux label when
// it has one, so nginx reads it exactly as it read the old one; a file with
// nothing to copy from keeps 0600 and the Plugin's own owner, which under the
// Agent is root.
func write(path string, data []byte, out io.Writer) (previous, error) {
	var old previous
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if old.data, err = os.ReadFile(path); err != nil {
			return old, err
		}
		old.info = info
	case !errors.Is(err, os.ErrNotExist):
		return old, err
	}
	if err := writeAtomic(path, data, old.info); err != nil {
		return old, fmt.Errorf("writing %s: %w", path, err)
	}
	fmt.Fprintf(out, "wrote %s (%s)\n", path, describePerms(path, old.info))
	return old, nil
}

func writeAtomic(path string, data []byte, like os.FileInfo) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".easyssl-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, defaultMode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // a no-op once the rename has succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if like != nil {
		if err := os.Chmod(tmp, like.Mode().Perm()); err != nil {
			return err
		}
		if st, ok := like.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
			if err := os.Chown(tmp, int(st.Uid), int(st.Gid)); err != nil {
				return err
			}
		}
		if err := copyLabel(path, tmp); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func describePerms(path string, like os.FileInfo) string {
	info, err := os.Stat(path)
	if err != nil {
		return "?"
	}
	owner := ""
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = fmt.Sprintf(", owner %d:%d", st.Uid, st.Gid)
	}
	how := "copied from the file it replaced"
	if like == nil {
		how = "a new file"
	}
	return fmt.Sprintf("mode %04o%s, %s", info.Mode().Perm(), owner, how)
}

// restore puts back what write replaced, or removes a file that did not exist
// before. Best effort and reported: the run is already failing, and what it
// could not undo is what the operator needs to read.
func restore(path string, old previous, stdout, stderr io.Writer) {
	var err error
	if old.info == nil {
		err = os.Remove(path)
	} else {
		err = writeAtomic(path, old.data, old.info)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "could not put back %s: %v\n", path, err)
		return
	}
	if old.info == nil {
		fmt.Fprintf(stdout, "removed %s, which did not exist before\n", path)
	} else {
		fmt.Fprintf(stdout, "put back the previous %s\n", path)
	}
}

// joinPEM is the certificate followed by its chain, each ending in one newline.
func joinPEM(cert, chain string) string {
	out := strings.TrimRight(cert, "\n") + "\n"
	if c := strings.TrimSpace(chain); c != "" {
		out += c + "\n"
	}
	return out
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
