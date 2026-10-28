package ops

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

// How a master was started, so the test and reload commands, and the gate
// discovery runs, see what the master sees. A master started with `-p` reads
// relative paths under that prefix, and one started with `-g "pid ...;"`
// keeps its pid somewhere its configuration does not say: `nginx -s reload`
// without the same flags reads another pid file and signals whatever process
// that names, or fails.

// build is what a binary was compiled with, from `nginx -V`.
type build struct {
	prefix, conf, errorLog, pid string
}

func buildOf(exe string) build {
	out, _ := exec.Command(exe, "-V").CombinedOutput() // on stderr
	return buildFrom(string(out))
}

// buildFrom reads `nginx -V`. A distribution's build names every path; a build
// from source often names only --prefix, or nothing, and nginx then uses its
// defaults under the prefix, /usr/local/nginx by default. Found on a BusyBox
// host running nginx compiled with --prefix alone.
func buildFrom(v string) build {
	b := build{prefix: "/usr/local/nginx", conf: "conf/nginx.conf", errorLog: "logs/error.log", pid: "logs/nginx.pid"}
	for _, tok := range strings.Fields(v) {
		for flag, dst := range map[string]*string{"--prefix=": &b.prefix, "--conf-path=": &b.conf,
			"--error-log-path=": &b.errorLog, "--pid-path=": &b.pid} {
			if p, ok := strings.CutPrefix(tok, flag); ok {
				*dst = p
			}
		}
	}
	return b
}

// under is p relative to prefix, as nginx resolves a relative path.
func under(prefix, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(prefix, p)
}

// nginxFlags are the options nginx takes, which end a `-g` value.
var nginxFlags = map[string]bool{"-c": true, "-p": true, "-e": true, "-g": true, "-s": true,
	"-t": true, "-T": true, "-q": true, "-v": true, "-V": true, "-h": true, "-?": true}

// startup is what a master's command line says about its paths.
type startup struct {
	config, prefix, globals string // -c, -p and -g as given
}

// startupOf reads the flags back out of a master's title, which nginx sets to
// "nginx: master process" and its arguments joined by spaces. Where they were
// split is lost, so a `-g` value runs to the next flag nginx knows.
func startupOf(title string) startup {
	var s startup
	f := strings.Fields(strings.TrimPrefix(title, "nginx: master process"))
	if len(f) > 0 {
		f = f[1:] // the binary as invoked
	}
	for i := 0; i < len(f); i++ {
		if len(f[i]) < 2 || f[i][0] != '-' || !nginxFlags[f[i][:2]] {
			continue
		}
		flag, val := f[i][:2], f[i][2:] // nginx also takes "-c/path"
		if val == "" && flag != "-g" && i+1 < len(f) && strings.Contains("-c-p-e-s", flag) {
			i++
			val = f[i]
		}
		switch flag {
		case "-c":
			s.config = val
		case "-p":
			s.prefix = val
		case "-g":
			words := []string{}
			if val != "" {
				words = append(words, val)
			}
			for i+1 < len(f) && !nginxFlags[f[i+1]] {
				i++
				words = append(words, f[i])
			}
			s.globals = strings.Join(words, " ")
		}
	}
	return s
}

// replayed is the part of a `-g` value a test or a signal has to repeat: all
// of it but `daemon` and `master_process`, which only say how the master runs
// and which Debian's and the Docker image's units always pass. A value with
// quotes is kept whole, since splitting it on `;` could cut inside them.
func replayed(globals string) string {
	if strings.ContainsAny(globals, `"'`) {
		return globals
	}
	var keep []string
	for _, d := range strings.Split(globals, ";") {
		f := strings.Fields(d)
		if len(f) == 0 || f[0] == "daemon" || f[0] == "master_process" {
			continue
		}
		keep = append(keep, strings.Join(f, " ")+";")
	}
	return strings.Join(keep, " ")
}

// startFrom fills in where the master's prefix and configuration are, and
// what of its command line the commands repeat.
func startFrom(in *instance, title string) {
	s := startupOf(title)
	in.build = buildOf(in.Exe)
	in.Prefix = in.build.prefix
	if s.prefix != "" {
		in.Prefix, in.PrefixGiven = s.prefix, true
		if !filepath.IsAbs(in.Prefix) {
			// Relative to the directory it was started in.
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", in.PID)); err == nil {
				in.Prefix = filepath.Join(cwd, in.Prefix)
			}
		}
	}
	in.ConfigPath = under(in.Prefix, in.build.conf)
	if s.config != "" {
		in.ConfigPath = under(in.Prefix, s.config)
	}
	in.Globals = replayed(s.globals)
}

// words is the binary and the flags every command for this master repeats:
// -p when it was given one, -c when its configuration is not the one the
// binary would read with that prefix, and what -g has to keep.
func (in *instance) words() []string {
	w := []string{in.Exe}
	if in.PrefixGiven {
		w = append(w, "-p", in.Prefix)
	}
	if in.ConfigPath != "" && in.ConfigPath != under(in.Prefix, in.build.conf) {
		w = append(w, "-c", in.ConfigPath)
	}
	if in.Globals != "" {
		w = append(w, "-g", in.Globals)
	}
	return w
}

// command is words quoted for the shell the settings run through, then args.
func (in *instance) command(args ...string) string {
	var q []string
	for _, w := range in.words() {
		q = append(q, shellQuote(w))
	}
	return strings.Join(append(q, args...), " ")
}

// pidFile is the file this master's own `nginx -s reload` reads its pid from:
// the main-level `pid` of its configuration, else one in -g, else the
// compiled path, relative to the prefix.
func (in *instance) pidFile() string {
	p := in.build.pid
	if payload, err := crossplane.Parse(in.ConfigPath, &crossplane.ParseOptions{}); err == nil && len(payload.Config) > 0 {
		for _, l := range flatten(payload, payload.Config[0].Parsed, payload.Config[0].File, 0) {
			if l.d.Directive == "pid" && len(l.d.Args) > 0 {
				p = l.d.Args[0]
			}
		}
	}
	for _, d := range strings.Split(in.Globals, ";") {
		if f := strings.Fields(d); len(f) == 2 && f[0] == "pid" {
			p = f[1]
		}
	}
	return under(in.Prefix, p)
}

// errGuard is a signal reload refused because it would not reach the master.
var errGuard = errors.New("the reload would not reach this master")

// guard runs before the master's own `nginx -s reload`, which sends SIGHUP to
// whatever pid its pid file holds: a stale file can name a process that is
// not nginx at all. It passes only while that file names this master and the
// master still runs the binary it ran. A service manager's reload needs none
// of this: the manager knows its own process.
func (in *instance) guard() error {
	pf := in.pidFile()
	b, err := os.ReadFile(pf)
	if err != nil {
		return fmt.Errorf("%w: its pid file %s cannot be read (%v)", errGuard, pf, err)
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(string(b))); n != in.PID {
		return fmt.Errorf("%w: its pid file %s holds %q, not master %d", errGuard, pf, strings.TrimSpace(string(b)), in.PID)
	}
	if exe := exeOf(in.PID); exe != in.Exe {
		return fmt.Errorf("%w: pid %d no longer runs %s", errGuard, in.PID, in.Exe)
	}
	return nil
}
