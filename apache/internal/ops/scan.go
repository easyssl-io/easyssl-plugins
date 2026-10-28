package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
)

// Finding the running Apache masters and working out, for each, how it was
// started: which binary, which arguments, which environment and which user,
// because every command run against an instance has to be run the way the
// instance runs or it tests and reloads something else. Each derivation is
// checked against the instance itself: the PidFile its configuration names
// must hold the master's pid.

// master is one running Apache parent process.
type master struct {
	PID, PPID int
	Exe       string // /proc/<pid>/exe: argv[0] can name a path that is only a symlink to it
	ParentExe string
	Version   string
	Argv      []string

	// Replay is the subset of the master's arguments that decide what it
	// loads: -d, -f, -D, -C and -c, in that order. Every command run against
	// the instance repeats them.
	Replay []string
	// Env is the master's environment minus what belongs to the process that
	// started it rather than to its configuration (dropped).
	Env  []string
	Cred cred

	Supervisor supervisor
	// Graceful is set when no supervisor reloads this master, so the reload is
	// this Plugin's own `-k graceful`, which needs a guard (guard) because it
	// starts a new server when the PidFile names no running master.
	Graceful bool

	// From the configuration test (-t -D DUMP_RUN_CFG), run as the instance.
	GateErr    error
	ServerRoot string
	PidFile    string
	ErrorLog   string
	PidFilePID int

	// What a restart outside any supervisor reproduces (restart.go).
	Umask  string
	NoFile string

	// LogMark is the error log's size right before deploy's reload.
	LogMark int64
}

// cred is the filesystem uid and gid and the supplementary groups: what the
// kernel checks when the process opens a file, read from /proc/<pid>/status.
type cred = hostfile.Cred

// supervisor is what started a master and, where it owns reloading, the name
// it is known by there.
type supervisor struct {
	Kind string // "systemd", "openrc", "runit", or "" for none
	Name string // the unit, the service, or the runsv service directory
}

// dropped are variables of a master's environment that belong to the process
// manager that started it, not to the configuration: handing NOTIFY_SOCKET to
// a test run would let it talk to systemd as if it were the service, and the
// pressure variables name the service's own cgroup files.
var dropped = regexp.MustCompile(`^(NOTIFY_SOCKET|LISTEN_[A-Z_]+|INVOCATION_ID|JOURNAL_STREAM|MANAGERPID|MANAGERPIDFDID|MAINPID|MAINPIDFDID|SYSTEMD_EXEC_PID|WATCHDOG_PID|WATCHDOG_USEC|(MEMORY|CPU|IO)_PRESSURE_(WATCH|WRITE)|FDSTORE|TRIGGER_[A-Z_]+|REMOTE_ADDR|REMOTE_PORT|SO_COOKIE|SERVICE_RESULT|EXIT_CODE|EXIT_STATUS|MONITOR_[A-Z_]+|DEBUG_INVOCATION|PIDFILE)=`)

type proc struct {
	pid, ppid int
	exe       string
}

// scan lists the running Apache masters, each derived (derive). It needs root:
// the exe link and the environment of a root-owned process are unreadable
// otherwise, and a command derived without them would look like an answer
// while being a guess.
func scan() ([]*master, error) {
	if os.Geteuid() != 0 {
		return nil, worded{T("apache.warning.needs_root",
			"discovery needs root, to read which binary each Apache master runs and with which environment")}
	}
	procs, err := readProcs()
	if err != nil {
		return nil, worded{T("apache.warning.proc_unreadable",
			"reading /proc (discovery works on Linux only): {error}", "error", err)}
	}
	byPID := map[int]proc{}
	for _, p := range procs {
		byPID[p.pid] = p
	}
	versions := map[string]string{} // exe -> version, "" when not Apache
	var out []*master
	for _, p := range procs {
		if !isApache(p.exe, versions) {
			continue
		}
		// A master's parent runs some other binary; a worker's parent is the
		// master. This is what tells the two apart, since Apache, unlike nginx,
		// does not mark the master in its process title.
		if byPID[p.ppid].exe == p.exe {
			continue
		}
		m := &master{PID: p.pid, PPID: p.ppid, Exe: p.exe, ParentExe: byPID[p.ppid].exe, Version: versions[p.exe]}
		derive(m)
		out = append(out, m)
	}
	return out, nil
}

func readProcs() ([]proc, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || exe == "" { // a kernel thread, or gone meanwhile
			continue
		}
		out = append(out, proc{pid: pid, ppid: ppidOf(pid), exe: strings.TrimSuffix(exe, " (deleted)")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out, nil
}

// ppidOf takes the parent pid from after the last ')' of /proc/<pid>/stat,
// because the process name inside the parentheses may contain both spaces and
// ')'.
func ppidOf(pid int) int {
	s := procFile(pid, "stat")
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}

func procFile(pid int, name string) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	return string(b)
}

// apacheName limits which binaries are asked for their version at all, so the
// scan never executes an arbitrary program found running on the host.
var apacheName = regexp.MustCompile(`(?i)(httpd|apache)`)

func isApache(exe string, cache map[string]string) bool {
	if v, ok := cache[exe]; ok {
		return v != ""
	}
	cache[exe] = ""
	if !apacheName.MatchString(filepath.Base(exe)) {
		return false
	}
	out, _ := runCmd(nil, nil, exe, "-v")
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "Server version: "); ok && strings.HasPrefix(v, "Apache/") {
			cache[exe] = v
		}
	}
	return cache[exe] != ""
}

// valueOpts are httpd's options that take a value: "k:" plus
// AP_SERVER_BASEARGS, "C:c:D:d:E:e:f:vVlLtTSMh?X" (server/mpm_unix.c and
// include/http_main.h in httpd 2.4). The value is attached (-DFOO) or the next
// argument (-D FOO).
const valueOpts = "CcDdEefk"

func derive(m *master) {
	m.Argv = splitNUL(procFile(m.PID, "cmdline"))
	m.Replay = replayOf(m.Argv)
	m.Cred = credOf(m.PID)
	m.Env = environOf(m.PID)
	m.Supervisor = supervisorOf(m)
	m.Graceful = m.Supervisor.Kind == "" || m.Supervisor.Kind == "runit"
	m.Umask, m.NoFile = umaskOf(m.PID), noFileOf(m.PID)

	out, err := m.run(context.Background(), "-t", "-D", "DUMP_RUN_CFG")
	if err != nil {
		m.GateErr = errors.New(firstError(out, err))
	}
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "ServerRoot: "); ok {
			m.ServerRoot = strings.Trim(v, `"`)
		}
		if v, ok := strings.CutPrefix(l, "PidFile: "); ok {
			m.PidFile = strings.Trim(v, `"`)
		}
		if v, ok := strings.CutPrefix(l, "Main ErrorLog: "); ok {
			m.ErrorLog = strings.Trim(v, `"`)
		}
	}
	m.PidFilePID = pidIn(m.PidFile)
}

// replayOf picks out of a master's argv the options that decide what it loads,
// in the order Replay documents.
func replayOf(argv []string) []string {
	var d, f string
	var defs, pre, post, out []string
	args := argv
	if len(args) > 0 {
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' || !strings.ContainsRune(valueOpts, rune(a[1])) {
			continue
		}
		v := a[2:]
		if v == "" && i+1 < len(args) {
			i++
			v = args[i]
		}
		switch a[1] {
		case 'd':
			d = v
		case 'f':
			f = v
		case 'D':
			defs = append(defs, v)
		case 'C':
			pre = append(pre, v)
		case 'c':
			post = append(post, v)
		}
	}
	if d != "" {
		out = append(out, "-d", d)
	}
	if f != "" {
		out = append(out, "-f", f)
	}
	for _, v := range defs {
		out = append(out, "-D", v)
	}
	for _, v := range pre {
		out = append(out, "-C", v)
	}
	for _, v := range post {
		out = append(out, "-c", v)
	}
	return out
}

func splitNUL(s string) []string {
	s = strings.TrimRight(s, "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

func pidIn(path string) int {
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// credOf reads the filesystem ids (the last field of Uid: and Gid:) and the
// supplementary groups, which are what decide whether the master can open a
// file. They are applied as they are rather than through `sudo -u`, which
// would look the groups up again and could get a different answer from the
// one the master started with.
func credOf(pid int) cred {
	var c cred
	for _, l := range strings.Split(procFile(pid, "status"), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "Uid:", "Gid:":
			if len(f) == 5 {
				n, _ := strconv.ParseUint(f[4], 10, 32)
				if f[0] == "Uid:" {
					c.UID = uint32(n)
				} else {
					c.GID = uint32(n)
				}
			}
		case "Groups:":
			for _, g := range f[1:] {
				n, _ := strconv.ParseUint(g, 10, 32)
				c.Groups = append(c.Groups, uint32(n))
			}
		}
	}
	return c
}

func environOf(pid int) []string {
	var env []string
	for _, kv := range splitNUL(procFile(pid, "environ")) {
		if strings.Contains(kv, "=") && !dropped.MatchString(kv) {
			env = append(env, kv)
		}
	}
	return env
}

// keptEnv is the part of the environment the graceful command carries: what a
// configuration plausibly reads (Debian's ${APACHE_RUN_DIR} and the like), and
// none of what the shell that started the master happened to hold.
func keptEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if k == "PATH" || k == "LANG" || k == "LD_LIBRARY_PATH" || strings.HasPrefix(k, "APACHE") || strings.HasPrefix(k, "HTTPD") {
			out = append(out, kv)
		}
	}
	return out
}

// runEnv is the environment every command against the instance runs with: the
// one its reload will get. A supervisor reloads with the service's own, which
// is the master's; the graceful command carries keptEnv.
func (m *master) runEnv() []string {
	if m.Graceful {
		return keptEnv(m.Env)
	}
	return m.Env
}

// run runs the master's binary with its arguments repeated, its environment and,
// for a master that is not root, its credentials, so a file the master cannot
// reach is not reachable here either.
func (m *master) run(ctx context.Context, args ...string) (string, error) {
	var c *syscall.Credential
	if !m.Cred.IsRoot() {
		c = m.Cred.Sys()
	}
	return runCmd(c, m.runEnv(), m.Exe, append(append([]string{}, m.Replay...), args...)...)
}

// command is the binary with its repeated arguments and args, as one shell
// line for a setting. The environment is not part of it: it is the instance's,
// applied by deploy when it runs the setting, and writing it into the setting
// would store whatever the master's environment holds on the Server.
func (m *master) command(args ...string) string {
	words := append([]string{m.Exe}, m.Replay...)
	words = append(words, args...)
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = shellQuote(w)
	}
	return strings.Join(q, " ")
}

func (m *master) testCommand() string { return m.command("-t") }

func (m *master) reloadCommand() string {
	switch m.Supervisor.Kind {
	case "systemd":
		return "systemctl reload " + shellQuote(m.Supervisor.Name)
	case "openrc":
		return "rc-service " + shellQuote(m.Supervisor.Name) + " reload"
	}
	// runit's `sv reload` sends SIGHUP, which Apache treats as a full restart,
	// so a runit master gets the graceful command too.
	return m.command("-k", "graceful")
}

// supervisorOf names what manages the master and owns its reload. The checks
// run in order and the first answer wins: on a systemd host the cgroup decides.
func supervisorOf(m *master) supervisor {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		// The systemd hierarchy is the unified one ("0::") or, under cgroup
		// v1, the named one ("name=systemd").
		for _, l := range strings.Split(strings.TrimSpace(procFile(m.PID, "cgroup")), "\n") {
			if !strings.HasPrefix(l, "0::") && !strings.Contains(l, ":name=systemd:") {
				continue
			}
			// The leaf names the unit: a session-N.scope is a login, not a
			// service, and a user@N.service never is the leaf.
			unit := filepath.Base(l[strings.LastIndexByte(l, ':')+1:])
			if strings.HasSuffix(unit, ".service") && systemctlShow(unit, "ExecReload") != "" {
				return supervisor{"systemd", unit}
			}
			return supervisor{}
		}
	}
	if svc := openrcService(m.PID); svc != "" {
		return supervisor{"openrc", svc}
	}
	if filepath.Base(m.ParentExe) == "runsv" {
		dir, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", m.PPID))
		return supervisor{"runit", dir}
	}
	return supervisor{}
}

func systemctlShow(unit, prop string) string {
	out, err := exec.Command("systemctl", "show", unit, "-p", prop, "--value").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// openrcService finds the started OpenRC service whose recorded pid file holds
// this master's pid, and which defines reload. Identity comes from the pid
// file OpenRC recorded, never from the text of an init script.
func openrcService(pid int) string {
	started, err := os.ReadDir("/run/openrc/started")
	if err != nil {
		return ""
	}
	for _, e := range started {
		svc := e.Name()
		if pidIn(openrcPIDFile(svc)) != pid {
			continue
		}
		if !definesReload(svc) {
			return ""
		}
		return svc
	}
	return ""
}

func openrcPIDFile(svc string) string {
	if b, err := os.ReadFile(filepath.Join("/run/openrc/options", svc, "pidfile")); err == nil {
		return strings.TrimSpace(string(b))
	}
	entries, err := os.ReadDir(filepath.Join("/run/openrc/daemons", svc))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("/run/openrc/daemons", svc, e.Name()))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "pidfile="); ok {
				return v
			}
		}
	}
	return ""
}

func definesReload(svc string) bool {
	f, err := os.Open(filepath.Join("/etc/init.d", svc))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); strings.HasPrefix(t, "reload()") || strings.Contains(t, `extra_started_commands="`) && strings.Contains(t, "reload") {
			return true
		}
	}
	return false
}

func umaskOf(pid int) string {
	for _, l := range strings.Split(procFile(pid, "status"), "\n") {
		if v, ok := strings.CutPrefix(l, "Umask:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func noFileOf(pid int) string {
	for _, l := range strings.Split(procFile(pid, "limits"), "\n") {
		if strings.HasPrefix(l, "Max open files") {
			if f := strings.Fields(strings.TrimPrefix(l, "Max open files")); len(f) > 0 {
				return f[0]
			}
		}
	}
	return ""
}

// guard runs right before a graceful-command reload. `-k graceful` signals
// whatever pid the PidFile holds, and when that process is not running it
// starts a new server instead (ap_signal_server in httpd's server/mpm_unix.c),
// so the reload runs only while the PidFile still names this master and this
// master still runs the same binary. A supervisor's reload needs none of this:
// the supervisor knows whether its service runs.
func (m *master) guard() error {
	if m.PidFile == "" {
		return errors.New("the configuration test reported no PidFile")
	}
	if n := pidIn(m.PidFile); n != m.PID {
		return fmt.Errorf("the PidFile %s holds %d, not master %d", m.PidFile, n, m.PID)
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", m.PID))
	if err != nil {
		return fmt.Errorf("master %d is not running", m.PID)
	}
	if exe = strings.TrimSuffix(exe, " (deleted)"); exe != m.Exe {
		return fmt.Errorf("pid %d now runs %s, not %s", m.PID, exe, m.Exe)
	}
	return nil
}

func (m *master) alive() bool {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", m.PID))
	return err == nil && strings.TrimSuffix(exe, " (deleted)") == m.Exe
}

// runCmd runs a program with the given environment (nil: this process's) and
// credentials (nil: this process's), with combined output.
func runCmd(c *syscall.Credential, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	if c != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: c}
	}
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	err := cmd.Run()
	return b.String(), err
}

// firstError is the line of httpd's output that says what went wrong: the first
// mentioning an error or carrying an AH code, except AH00558, the harmless
// warning about a missing global ServerName.
func firstError(out string, err error) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "rror") || strings.Contains(l, "AH0") && !strings.Contains(l, "AH00558") {
			return strings.TrimSpace(l)
		}
	}
	return err.Error()
}

// shellQuote makes one word of s for the `/bin/sh -e -c` the test and reload
// settings run through. Paths come from a running process on the host and are
// attacker-influenced while the command runs as root: a space would split
// one, and a `;` would run what follows.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-@:+,=") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
