package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// Starting a master again after a reload made it exit. The files are already
// put back when this runs, so a failure caused by the new files is undone by
// starting Apache as it was started before; a failure with another cause (a
// port another process took, a module failing) fails the start too, and the
// output says so.

const restartWait = 10 * time.Second

// recoverMaster starts m again by whatever started it, and reports the run as
// failed in every case: the Deployment did not install its Certificate.
func recoverMaster(ctx context.Context, m *master, s *serverCfg, stdout, stderr io.Writer, cause error) error {
	if errors.Is(cause, tlscheck.ErrGone) {
		fmt.Fprintf(stdout, "Apache (pid %d) stopped during the reload\n", m.PID)
	} else {
		fmt.Fprintf(stdout, "Apache (pid %d) stopped during the reload: %v\n", m.PID, cause)
	}
	for _, l := range emergLines(m) {
		fmt.Fprintf(stdout, "error log: %s\n", l)
	}
	waitGone(m)
	how, err := restart(ctx, m, s, stdout)
	if err != nil {
		return fmt.Errorf("the reload stopped Apache, the previous files were put back, and it could not be started again (%s): %v", how, err)
	}
	if back := waitBack(m); back != 0 {
		return fmt.Errorf("the reload stopped Apache; the previous files were put back and it was started again (%s, pid %d)", how, back)
	}
	return fmt.Errorf("the reload stopped Apache, the previous files were put back, and it is not running %s after starting it again (%s)", restartWait, how)
}

// waitGone waits for a master that stopped to be gone from /proc. Its exe link
// goes away early in its exit, and it then stays a zombie until init reaps it,
// about 0.6 s on Alpine, while start-stop-daemon counts it as running and
// refuses to start the service.
func waitGone(m *master) {
	deadline := time.Now().Add(restartWait)
	for procFile(m.PID, "stat") != "" && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
}

// restart starts m the way it was started, and names how.
func restart(ctx context.Context, m *master, s *serverCfg, stdout io.Writer) (string, error) {
	if needsDialog(m, s) {
		return "not attempted", fmt.Errorf("a key it loads is encrypted and its passphrase is asked for at a terminal (SSLPassPhraseDialog builtin), so it has to be started by hand: %s", strings.Join(m.Argv, " "))
	}
	switch {
	case m.Supervisor.Kind == "systemd":
		return run(ctx, stdout, "systemctl", "start", m.Supervisor.Name)
	case m.Supervisor.Kind == "openrc":
		// OpenRC still records the service as started when its daemon exits
		// on its own, and then refuses to start it; the master is known to be
		// gone, so that record is reset first.
		if how, err := run(ctx, stdout, "rc-service", m.Supervisor.Name, "zap"); err != nil {
			return how, err
		}
		return run(ctx, stdout, "rc-service", m.Supervisor.Name, "start")
	case m.Supervisor.Kind == "runit":
		return "runsv " + m.Supervisor.Name + " starts it again", nil
	case m.PPID == 1 && foreground(m) && !onSystemd():
		return "init starts it again (respawn)", nil
	}
	return startSnapshot(ctx, m, stdout)
}

func run(ctx context.Context, stdout io.Writer, name string, args ...string) (string, error) {
	how := name + " " + strings.Join(args, " ")
	fmt.Fprintf(stdout, "$ %s\n", how)
	out, err := runCmd(nil, nil, name, args...)
	io.WriteString(stdout, out)
	return how, err
}

func onSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// foreground is a master that does not detach, which is how a process manager
// that restarts it on exit (runsv, BusyBox init's respawn) runs it.
func foreground(m *master) bool {
	for i, a := range m.Replay {
		if a == "-D" && i+1 < len(m.Replay) && m.Replay[i+1] == "FOREGROUND" {
			return true
		}
	}
	return false
}

// needsDialog reports a master loading an encrypted key whose passphrase
// mod_ssl asks for at a terminal, which an unattended start cannot answer.
func needsDialog(m *master, s *serverCfg) bool {
	if s.passDialog != "" && !strings.EqualFold(s.passDialog, "builtin") {
		return false
	}
	for _, p := range loadedPairs(m, s) {
		if b, err := os.ReadFile(p.key); err == nil && pemfile.EncryptedKey(b) {
			return true
		}
	}
	return false
}

// startSnapshot starts a master no process manager restarts, with what was
// read from it before the reload: its binary and arguments with `-k start`,
// its environment, its user, its umask and its open-file limit. On a systemd
// host it runs as a transient service rather than as a child of this
// Plugin, which runs inside the Agent's unit: there it would see the Agent's
// private /tmp (PrivateTmp=yes) and be killed with the Agent's control group
// whenever the Agent stops.
func startSnapshot(ctx context.Context, m *master, stdout io.Writer) (string, error) {
	script := `exec "$0" "$@"`
	if m.NoFile != "" {
		script = `ulimit -Sn ` + shellQuote(m.NoFile) + ` 2>/dev/null || true; ` + script
	}
	if m.Umask != "" {
		script = `umask ` + shellQuote(m.Umask) + `; ` + script
	}
	argv := append([]string{"/bin/sh", "-c", script, m.Exe}, m.Replay...)
	argv = append(argv, "-k", "start")
	if onSystemd() {
		return startTransient(ctx, m, argv, stdout)
	}
	how := strings.Join(argv[3:], " ")
	fmt.Fprintf(stdout, "$ %s\n", how)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = m.Env
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if !m.Cred.IsRoot() {
		cmd.SysProcAttr.Credential = m.Cred.Sys()
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if foreground(m) {
		// It never detaches, so it is left running rather than waited for.
		if err := cmd.Start(); err != nil {
			return how, err
		}
		return how, cmd.Process.Release()
	}
	err := cmd.Run() // httpd detaches and this returns
	io.WriteString(stdout, out.String())
	return how, err
}

func startTransient(ctx context.Context, m *master, argv []string, stdout io.Writer) (string, error) {
	// The environment goes through a root-only file rather than --setenv, which
	// would put every value on systemd-run's world-readable command line.
	envFile, err := os.CreateTemp("/run", "easyssl-apache-env-")
	if err != nil {
		return "systemd-run", err
	}
	defer os.Remove(envFile.Name())
	for _, kv := range m.Env {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Fprintf(envFile, "%s=\"%s\"\n", k, strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v))
	}
	if err := envFile.Close(); err != nil {
		return "systemd-run", err
	}
	unit := fmt.Sprintf("easyssl-apache-%d-%d", m.PID, time.Now().Unix())
	args := []string{"--unit", unit, "--description", "Apache restarted by easySSL after pid " + strconv.Itoa(m.PID) + " stopped",
		"-p", "EnvironmentFile=" + envFile.Name(), "-p", "WorkingDirectory=/"}
	if foreground(m) {
		args = append(args, "-p", "Type=simple")
	} else {
		args = append(args, "-p", "Type=forking", "-p", "PIDFile="+m.PidFile)
	}
	if !m.Cred.IsRoot() {
		args = append(args, "-p", fmt.Sprintf("User=%d", m.Cred.UID), "-p", fmt.Sprintf("Group=%d", m.Cred.GID))
		var gs []string
		for _, g := range m.Cred.Groups {
			gs = append(gs, strconv.FormatUint(uint64(g), 10))
		}
		if len(gs) > 0 {
			args = append(args, "-p", "SupplementaryGroups="+strings.Join(gs, " "))
		}
	}
	args = append(args, "--")
	args = append(args, argv...)
	_, err = run(ctx, stdout, "systemd-run", args...)
	return "systemd-run --unit " + unit, err
}

// waitBack waits for the PidFile to name a running master of the same binary,
// and returns its pid, 0 when none came.
func waitBack(m *master) int {
	deadline := time.Now().Add(restartWait)
	for {
		if n := pidIn(m.PidFile); n > 0 {
			exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", n))
			if err == nil && strings.TrimSuffix(exe, " (deleted)") == m.Exe {
				return n
			}
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// errorLogPath is the master's Main ErrorLog as a file, "" when it is written
// to syslog or a pipe.
func errorLogPath(m *master) string {
	path := m.ErrorLog
	if path == "" || strings.HasPrefix(path, "syslog") || strings.HasPrefix(path, "|") {
		return ""
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(m.ServerRoot, path)
	}
	return path
}

// markErrorLog records where the error log ends, right before the reload, so
// what the reload wrote can be told from what was there before.
func markErrorLog(m *master) {
	if fi, err := os.Stat(errorLogPath(m)); err == nil {
		m.LogMark = fi.Size()
	}
}

// emergLines are the emergency lines the error log gained since markErrorLog,
// which name why the master exited (AH00016 and the line before AH00020).
func emergLines(m *master) []string {
	path := errorLogPath(m)
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	from := m.LogMark
	if fi, err := f.Stat(); err != nil || fi.Size() < from {
		from = 0 // rotated since
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, ":emerg]") || strings.Contains(l, "[emerg]") {
			out = append(out, l)
		}
	}
	if len(out) > 5 {
		out = out[len(out)-5:]
	}
	return out
}
