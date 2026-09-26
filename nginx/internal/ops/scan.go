package ops

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// scan walks /proc and returns one instance per running nginx master, each
// with its commands and what its configuration loads.
//
// Must run as root, which the Agent does: /proc/<pid>/exe of a root-owned
// master is readable only by root, and a reload command derived without the
// binary would look like an answer while being a guess.
//
// The master is identified by the process title nginx sets for itself,
// "nginx: master process". Matching the executable name would also return
// every worker, and signalling a worker reloads nothing.
func scan() ([]instance, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("discovery needs root, to read which binary each nginx master runs")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc (discovery is Linux-only): %w", err)
	}
	var out []instance
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		// nginx overwrites its argv, so the fields arrive NUL-separated but
		// read as one title.
		title := strings.ReplaceAll(procFile(pid, "cmdline"), "\x00", " ")
		if !strings.HasPrefix(title, "nginx: master process") {
			continue
		}
		exe := exeOf(pid)
		if exe == "" {
			continue // exited between the listing and the read
		}
		in := instance{PID: pid, Exe: exe}
		in.ConfigPath = configOf(title, in.Exe)
		decide(&in)
		in.Certs, in.CertsErr = certificates(accepted, in.Exe, in.ConfigPath)
		out = append(out, in)
	}
	return out, nil
}

// accepted asks the instance's own binary whether it would load this
// configuration, and refuses to go further when it would not.
//
// The reason is that a rejected configuration describes nothing real. nginx
// will not load it, so it is not what the master is serving; and the master is
// still serving whatever it loaded last, which is no longer on disk. Parsing it
// anyway produces a list of certificates that belongs to neither state, and the
// list looks exactly like a correct one. On this host a single missing
// certificate file put the whole configuration in that condition while every
// other entry in it still parsed and reported cleanly.
//
// The gate is deliberately one-directional, which is the only reason it is
// sound. A failure is trustworthy: `nginx -t` runs outside the service's
// sandbox and so can see at least as much of the filesystem as the master, so a
// file it cannot open is a file the master cannot open either. A pass proves
// less — the master may run with PrivateTmp=yes and see a smaller filesystem,
// which is how a reload can fail on a host where `nginx -t` just succeeded. So
// this refuses on failure and does not promise anything on success.
//
// The instance's own binary and its own -c are used, since a second nginx on
// the host may be a different build with different compiled-in paths.
func accepted(exe, config string) error {
	out, err := exec.Command(exe, "-t", "-c", config).CombinedOutput()
	if err == nil {
		return nil
	}
	// nginx puts the reason on stderr, one [emerg] line, followed by a summary.
	// The first is the useful one; the rest repeats that the test failed.
	msg := "configuration test failed"
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "[emerg]"); i >= 0 {
			msg = strings.TrimSpace(line[i+len("[emerg]"):])
			// Drop nginx's "12345#12345: " process prefix.
			if j := strings.Index(msg, ": "); j >= 0 && j < 20 {
				msg = msg[j+2:]
			}
			break
		}
	}
	return fmt.Errorf("nginx rejects this configuration, so it was not parsed: %s", msg)
}

func procFile(pid int, name string) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	return string(b)
}

func exeOf(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

// configOf finds the configuration file: an explicit -c on the command line
// wins, otherwise the path the binary was compiled with.
func configOf(title, exe string) string {
	f := strings.Fields(title)
	for i, s := range f {
		if s == "-c" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return buildValue(exe, "--conf-path=")
}

// buildValue reads one compiled-in path out of `nginx -V`, whose output goes to
// stderr.
func buildValue(exe, key string) string {
	out, _ := exec.Command(exe, "-V").CombinedOutput()
	for _, tok := range strings.Fields(string(out)) {
		if strings.HasPrefix(tok, key) {
			return strings.TrimPrefix(tok, key)
		}
	}
	return ""
}

// A systemd unit name: letters, digits, and the punctuation systemd allows,
// ending in .service. No capture group, because the pattern is the whole thing
// being extracted; the hyphen is last in the class so it is a literal rather
// than a range.
var unitRe = regexp.MustCompile(`[A-Za-z0-9@_.-]+\.service`)

// decide fills in Reload. A service manager's own reload is preferred when it
// defines one, so the manager sees the reload; when it does not, the signal is
// the answer and not a lesser one, because the master reloads the same way
// whoever started it. That is why a unit without ExecReload is not a warning.
func decide(in *instance) {
	in.Test = testCommand(in)
	if unit := systemdUnit(in.PID); unit != "" {
		if systemctlShow(unit, "ExecReload") != "" {
			in.Reload = "systemctl reload " + unit
			return
		}
	}

	if svc := openrcService(in.PID); svc != "" {
		in.Reload = "rc-service " + svc + " reload"
		return
	}

	in.Reload = signalCommand(in)
}

// signalCommand is the fallback. -c is repeated only when the master was
// started with a config that is not the compiled-in default, because
// `nginx -s reload` resolves the pid file through the configuration and would
// otherwise read a different one.
func signalCommand(in *instance) string {
	return withConfig(in) + " -s reload"
}

// testCommand is the instance's own `-t`: same binary, same -c rule as the
// signal, since a test against another configuration says nothing about this
// master.
func testCommand(in *instance) string {
	return withConfig(in) + " -t"
}

// withConfig is the binary plus -c when the configuration is not that binary's
// compiled default, in which case naming it would be harmless but wrong.
func withConfig(in *instance) string {
	if in.ConfigPath != "" && in.ConfigPath != buildValue(in.Exe, "--conf-path=") {
		return fmt.Sprintf("%s -c %s", in.Exe, in.ConfigPath)
	}
	return in.Exe
}

// systemdUnit reads the unit name out of the process's cgroup. This asks which
// unit actually contains the process rather than assuming a name, so an nginx
// under a unit called something else is still identified.
func systemdUnit(pid int) string {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return ""
	}
	for _, line := range strings.Split(procFile(pid, "cgroup"), "\n") {
		if unit := unitRe.FindString(line); unit != "" {
			return unit
		}
	}
	return ""
}

func systemctlShow(unit, prop string) string {
	out, err := exec.Command("systemctl", "show", unit, "-p", prop, "--value").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// openrcService finds the started OpenRC service that owns this master, or "".
//
// Identity comes from the pid file OpenRC itself recorded when it started the
// daemon, never from the text of an init script. Reading the script was wrong
// twice over: a service is identified by what it is running, not by what its
// source happens to mention, and a single comment naming /usr/sbin/nginx in
// /etc/init.d/apache2 was enough to make apache2 answer for nginx — it sorts
// first, so it won.
//
// OpenRC writes /run/openrc/options/<svc>/pidfile for every service it started
// through start-stop-daemon, and /run/openrc/daemons/<svc>/NNN carries the same
// value on older versions. Whichever exists, the file it names holds the pid of
// the master OpenRC is supervising: if that is our pid, this is our service,
// and no other service can claim it.
//
// Services with no pid file are skipped rather than guessed at. That excludes
// every one-shot (hostname, localmount, sysctl), which is correct — a service
// with no daemon has nothing to reload.
func openrcService(pid int) string {
	started, err := os.ReadDir("/run/openrc/started")
	if err != nil {
		return ""
	}
	for _, e := range started {
		svc := e.Name()
		pidFile := openrcPIDFile(svc)
		if pidFile == "" {
			continue
		}
		b, err := os.ReadFile(pidFile)
		if err != nil {
			continue // the service is recorded but its pid file is gone
		}
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err != nil || n != pid {
			continue
		}
		// The service owns the process. It still has to support reloading:
		// `rc-service <svc> reload` on a script without one fails.
		if !definesReload(svc) {
			return ""
		}
		return svc
	}
	return ""
}

// openrcPIDFile returns the pid file OpenRC recorded for a started service.
func openrcPIDFile(svc string) string {
	// The modern location, one value per file.
	if b, err := os.ReadFile(filepath.Join("/run/openrc/options", svc, "pidfile")); err == nil {
		return strings.TrimSpace(string(b))
	}
	// Older OpenRC: key=value records under daemons/<svc>/, numbered per
	// daemon the service started.
	entries, err := os.ReadDir(filepath.Join("/run/openrc/daemons", svc))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		f, err := os.Open(filepath.Join("/run/openrc/daemons", svc, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "pidfile="); ok {
				f.Close()
				return v
			}
		}
		f.Close()
	}
	return ""
}

// definesReload reports whether a service's init script implements reload.
// Only the shape of the script matters here, not what it names, so a comment
// cannot influence it: the check is anchored to the start of a line.
func definesReload(svc string) bool {
	f, err := os.Open(filepath.Join("/etc/init.d", svc))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(strings.TrimSpace(sc.Text()), "reload()") {
			return true
		}
	}
	return false
}
