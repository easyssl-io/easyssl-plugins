package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// File names written into the run's working directory. Fullchain is the
// certificate followed by the chain, which is what most servers actually read.
const (
	certFile      = "cert.pem"
	chainFile     = "chain.pem"
	fullchainFile = "fullchain.pem"
	keyFile       = "key.pem"
)

// keyMode is the private key's mode. The other three are public material and
// are written 0644; only this one is a secret, and it exists for as long as one
// command takes to run.
const (
	keyMode      os.FileMode = 0o600
	materialMode os.FileMode = 0o644
)

// Install performs one certificate installation (FR-001, FR-002).
//
// It writes the material to files inside the run's working directory, runs the
// reload command with the four paths in its environment, and removes those
// files whatever happened — including when the command fails, which is the case
// that matters: a failed install must not leave a private key on disk. The
// Agent removes the whole working directory after every run, which is what
// also cleans up a run it had to kill; this cleanup is the Plugin doing its own
// half rather than relying on that.
//
// The returned response always describes the attempt: OK is the command's
// exit 0, and Output is one text carrying what the command printed, because the
// command ran inside this Plugin and only this answer crosses back (FR-013).
func Install(ctx context.Context, req InstallRequest) InstallResponse {
	var out strings.Builder
	fmt.Fprintf(&out, "%s %s · install\n", Name, Version())

	command, ok := req.Settings["reload"]
	if !ok || strings.TrimSpace(command) == "" {
		// The Server refuses to queue a Deployment whose required settings have
		// no value, so reaching here means something upstream is wrong rather
		// than that the user forgot; say so plainly instead of running nothing
		// and reporting success.
		out.WriteString("install failed: no reload command was supplied, and this Plugin installs nothing by itself\n")
		return InstallResponse{ContractVersion: ContractVersion, OK: false, Output: out.String()}
	}

	dir, cleanupDir, err := workDir(req.WorkDir)
	if err != nil {
		fmt.Fprintf(&out, "install failed: could not prepare the working directory: %v\n", err)
		return InstallResponse{ContractVersion: ContractVersion, OK: false, Output: out.String()}
	}
	if cleanupDir != nil {
		defer cleanupDir()
	}

	paths, err := writeMaterial(dir, req)
	// Remove what was written whether or not everything was: a partial write
	// can still have left the key.
	defer removeAll(paths)
	if err != nil {
		fmt.Fprintf(&out, "install failed: could not write the certificate material: %v\n", err)
		return InstallResponse{ContractVersion: ContractVersion, OK: false, Output: out.String()}
	}

	fmt.Fprintf(&out, "wrote the certificate, chain, fullchain and key to %s\n", dir)
	out.WriteString("running the reload command\n")

	// /bin/sh -c, so the command may be a multi-line script and use anything a
	// shell offers. The script is on the shell's argv, which is the operator's
	// own text; the key never is, being in a file whose path is passed through
	// the environment (FR-002e).
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"EASYSSL_CERT_PATH="+paths[certFile],
		"EASYSSL_CHAIN_PATH="+paths[chainFile],
		"EASYSSL_FULLCHAIN_PATH="+paths[fullchainFile],
		"EASYSSL_KEY_PATH="+paths[keyFile],
	)
	// Combined, because a reload command's diagnostics are as much of the
	// record as its output and splitting them loses the order they happened in.
	combined, runErr := cmd.CombinedOutput()
	if len(combined) > 0 {
		out.Write(combined)
		if combined[len(combined)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	if runErr != nil {
		fmt.Fprintf(&out, "install failed: the reload command %s\n", describeExit(runErr))
		return InstallResponse{ContractVersion: ContractVersion, OK: false, Output: out.String()}
	}
	out.WriteString("install succeeded: the reload command exited 0\n")
	return InstallResponse{ContractVersion: ContractVersion, OK: true, Output: out.String()}
}

// workDir resolves where this run writes. The Agent supplies one it will
// remove afterwards; when nothing was supplied — running the binary by hand —
// one is created here and removed by the returned function, so the Plugin is
// usable on its own without ever leaving key material behind.
func workDir(supplied string) (string, func(), error) {
	if supplied != "" {
		if err := os.MkdirAll(supplied, 0o700); err != nil {
			return "", nil, err
		}
		return supplied, nil, nil
	}
	dir, err := os.MkdirTemp("", "easyssl-generic-cli-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// writeMaterial writes the four files and returns their paths by name. It
// returns whatever it managed to write alongside any error, so the caller can
// remove a partial set.
func writeMaterial(dir string, req InstallRequest) (map[string]string, error) {
	paths := map[string]string{
		certFile:      filepath.Join(dir, certFile),
		chainFile:     filepath.Join(dir, chainFile),
		fullchainFile: filepath.Join(dir, fullchainFile),
		keyFile:       filepath.Join(dir, keyFile),
	}
	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{certFile, req.CertificatePem, materialMode},
		{chainFile, req.ChainPem, materialMode},
		{fullchainFile, joinPEM(req.CertificatePem, req.ChainPem), materialMode},
		{keyFile, req.PrivateKeyPem, keyMode},
	}
	for _, f := range files {
		// WriteFile's mode applies only when it creates the file, and the key
		// must never exist even briefly at a wider mode, so the directory is
		// ours and freshly made: nothing it could be reusing.
		if err := os.WriteFile(paths[f.name], []byte(f.content), f.mode); err != nil {
			return paths, err
		}
	}
	return paths, nil
}

// joinPEM concatenates the certificate and its chain with exactly one newline
// between them, whatever trailing newlines each carried.
func joinPEM(cert, chain string) string {
	cert = strings.TrimRight(cert, "\n")
	chain = strings.TrimLeft(strings.TrimRight(chain, "\n"), "\n")
	if chain == "" {
		return cert + "\n"
	}
	return cert + "\n" + chain + "\n"
}

func removeAll(paths map[string]string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// describeExit turns the command's error into the phrase that reads naturally
// after "the reload command".
func describeExit(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exited %d", exitErr.ExitCode())
	}
	return fmt.Sprintf("could not be run: %v", err)
}
