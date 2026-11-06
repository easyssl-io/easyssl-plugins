package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// File names written into the run's working directory. Fullchain is the
// certificate followed by the chain, which is what most servers actually read.
const (
	certificateFile = "cert.pem"
	chainFile       = "chain.pem"
	fullchainFile   = "fullchain.pem"
	keyFile         = "key.pem"
)

// keyMode is the private key's mode. The other three are public material and
// are written 0644; only this one is a secret, and it exists for as long as one
// command takes to run.
const (
	keyMode      os.FileMode = 0o600
	materialMode os.FileMode = 0o644
)

// Deploy carries out one Deployment: it writes the material to files inside the
// run's working directory, runs the install command with the four paths in its
// environment, and removes those files whatever happened, because a failed
// install must not leave a private key on disk. The Agent removes the whole
// working directory after every run too; this cleanup is the Plugin doing its
// own half.
//
// There is no response document: the exit status is the answer, and the
// command's stdout and stderr pass through as this Plugin's own, so the Agent
// records one transcript and can set stderr apart on screen.
func Deploy(ctx context.Context, req DeployRequest, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "%s %s · deploy\n", Name, Version())

	command, ok := req.Settings[SettingInstall]
	if !ok || strings.TrimSpace(command) == "" {
		// The Server refuses to queue a Deployment whose required settings have no
		// value, so reaching here means something upstream is wrong. Say so instead
		// of running nothing and reporting success.
		return errors.New("no install command was supplied, and this Plugin installs nothing by itself")
	}

	dir, cleanupDir, err := workDir(req.WorkDir)
	if err != nil {
		return fmt.Errorf("could not prepare the working directory: %w", err)
	}
	if cleanupDir != nil {
		defer cleanupDir()
	}

	paths, err := writeMaterial(dir, req)
	// Remove what was written whether or not everything was: a partial write
	// can still have left the key.
	defer removeAll(paths)
	if err != nil {
		return fmt.Errorf("could not write the certificate material: %w", err)
	}

	fmt.Fprintf(stdout, "wrote the certificate, chain, fullchain and key to %s\n", dir)
	fmt.Fprintln(stdout, "running the install command")

	// /bin/sh -c, so the command may be a multi-line script. The script is on the
	// shell's argv, which is the operator's own text; the key never is, being in a
	// file whose path is passed through the environment.
	//
	// -e, because a script's exit status is its last line's: without it `ls
	// /missing; echo done` exits 0 and a Target is marked healthy with nothing
	// installed. It is the shell's own flag rather than a line prepended to the
	// script, so it holds however the operator edits it; `|| true` lets a line
	// fail, and `set +e` on the first line opts out. POSIX -e only: pipefail is
	// not in every /bin/sh. And POSIX -e does not act on a failure on the left of
	// && or ||, or inside a pipeline, so `cp a b && reload; echo done` exits 0
	// when cp fails. The description and the template say so, and a test records
	// the limit.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-e", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"EASYSSL_CERT_PATH="+paths[certificateFile],
		"EASYSSL_CHAIN_PATH="+paths[chainFile],
		"EASYSSL_FULLCHAIN_PATH="+paths[fullchainFile],
		"EASYSSL_KEY_PATH="+paths[keyFile],
	)
	// The install command's stdout and stderr are this Plugin's own, so the Agent
	// records both in the order it received them and can set the second apart on
	// screen.
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if runErr := cmd.Run(); runErr != nil {
		// Only the returned error, which main writes to stderr. Saying it on stdout
		// as well would put the same sentence in the transcript twice.
		return fmt.Errorf("the install command %s", describeExit(runErr))
	}
	fmt.Fprintln(stdout, "deploy succeeded: the install command exited 0")
	return nil
}

// workDir resolves where this run writes. The Agent supplies one it will remove
// afterwards; when the binary is run by hand, one is created here and removed
// by the returned function, so no key material is left behind.
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
func writeMaterial(dir string, req DeployRequest) (map[string]string, error) {
	paths := map[string]string{
		certificateFile: filepath.Join(dir, certificateFile),
		chainFile:       filepath.Join(dir, chainFile),
		fullchainFile:   filepath.Join(dir, fullchainFile),
		keyFile:         filepath.Join(dir, keyFile),
	}
	// Only certificates are written, re-encoded, whatever text came with them:
	// the install command runs as root and may copy these anywhere.
	certificate, err := pemfile.Certificates(req.CertificatePem)
	if err != nil {
		return paths, err
	}
	chain, err := pemfile.Certificates(req.ChainPem)
	if err != nil {
		return paths, err
	}
	fullchain, err := pemfile.JoinPEM(req.CertificatePem, req.ChainPem)
	if err != nil {
		return paths, err
	}
	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{certificateFile, certificate, materialMode},
		{chainFile, chain, materialMode},
		{fullchainFile, fullchain, materialMode},
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

func removeAll(paths map[string]string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// describeExit turns the command's error into the phrase that reads naturally
// after "the install command".
func describeExit(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exited %d", exitErr.ExitCode())
	}
	return fmt.Sprintf("could not be run: %v", err)
}
