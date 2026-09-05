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

// Install performs one Certificate installation.
//
// It writes the material to files inside the run's working directory, runs the
// reload command with the four paths in its environment, and removes those
// files whatever happened — including when the command fails, which is the case
// that matters: a failed install must not leave a private key on disk. The
// Agent removes the whole working directory after every run, which is what
// also cleans up a run it had to kill; this cleanup is the Plugin doing its own
// half rather than relying on that.
//
// There is no response document. The exit status is the answer — nil here, a
// non-zero exit from main — and what happened is on stdout and stderr, which
// the Agent records in the order it received them. So this Plugin's narration
// and the reload command's output are one transcript, and the command's stderr
// arrives as stderr rather than as a labeled line inside a string, which is
// what lets the Agent set it apart on screen.
func Install(ctx context.Context, req InstallRequest, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "%s %s · install\n", Name, Version())

	command, ok := req.Settings["reload"]
	if !ok || strings.TrimSpace(command) == "" {
		// The Server refuses to queue a Deployment whose required settings have
		// no value, so reaching here means something upstream is wrong rather
		// than that the user forgot; say so plainly instead of running nothing
		// and reporting success.
		return errors.New("no reload command was supplied, and this Plugin installs nothing by itself")
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
	fmt.Fprintln(stdout, "running the reload command")

	// /bin/sh -c, so the command may be a multi-line script and use anything a
	// shell offers. The script is on the shell's argv, which is the operator's
	// own text; the key never is, being in a file whose path is passed through
	// the environment.
	//
	// -e, because a script's exit status is its last line's and nothing else's.
	// `ls /missing; echo done` exits 0, and this Plugin reported it as a
	// success while the copy that mattered had failed two lines up, which is
	// the one outcome a deployment step must not produce: a Target marked
	// healthy with nothing installed. With -e the first failing line ends the
	// script and the Deployment fails with that line as the last thing in its
	// output. It is the shell's own flag rather than a line prepended to the
	// script, so it holds whatever the operator wrote and however they edit it;
	// a line that is allowed to fail says so with `|| true`, and `set +e` on
	// the first line opts out for a script that wants last-line semantics.
	// POSIX -e only: pipefail is not in every /bin/sh. And POSIX -e acts on a
	// line's own status: a failure on the left of && or ||, or inside a
	// pipeline, does not end the script, so `cp a b && reload; echo done`
	// exits 0 when cp fails. The description and the template say so, and
	// the test for it records the limit rather than pretending -e has none.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-e", "-c", command)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"EASYSSL_CERT_PATH="+paths[certificateFile],
		"EASYSSL_CHAIN_PATH="+paths[chainFile],
		"EASYSSL_FULLCHAIN_PATH="+paths[fullchainFile],
		"EASYSSL_KEY_PATH="+paths[keyFile],
	)
	// Straight through. The reload command's stdout is this Plugin's stdout and
	// its stderr is this Plugin's stderr, so the Agent records both in the order
	// it received them and can set the second apart on screen. Nothing is
	// labeled here any more: this Plugin prefixed each line because one output
	// string could not say which stream a line came from, and that is no longer
	// the shape the answer takes.
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if runErr := cmd.Run(); runErr != nil {
		fmt.Fprintf(stdout, "install failed: the reload command %s\n", describeExit(runErr))
		return fmt.Errorf("the reload command %s", describeExit(runErr))
	}
	fmt.Fprintln(stdout, "install succeeded: the reload command exited 0")
	return nil
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
		certificateFile: filepath.Join(dir, certificateFile),
		chainFile:       filepath.Join(dir, chainFile),
		fullchainFile:   filepath.Join(dir, fullchainFile),
		keyFile:         filepath.Join(dir, keyFile),
	}
	files := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{certificateFile, req.CertificatePem, materialMode},
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
func joinPEM(certificate, chain string) string {
	certificate = strings.TrimRight(certificate, "\n")
	chain = strings.TrimLeft(strings.TrimRight(chain, "\n"), "\n")
	if chain == "" {
		return certificate + "\n"
	}
	return certificate + "\n" + chain + "\n"
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
