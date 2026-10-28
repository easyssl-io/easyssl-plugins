package ops

import (
	"os"
	"strconv"
	"strings"
	"time"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

// Configuration files edited since the master last loaded them. A reload
// applies every edit on disk, not only the new certificate, so a Deployment
// would put live whatever someone left half done, and a mistake in it would
// read as the Deployment's.

// clockSlack absorbs the coarseness of the moment below: the boot time it is
// computed from has whole seconds.
const clockSlack = 2 * time.Second

// loadedAt is when the master last loaded its configuration: when its newest
// worker started, since every reload starts new workers, or when the master
// itself started when it runs none. The pid file cannot say: nginx writes it
// at startup only.
func loadedAt(master int) (time.Time, bool) {
	var newest time.Time
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return newest, false
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || ppidOf(pid) != master {
			continue
		}
		title := strings.ReplaceAll(procFile(pid, "cmdline"), "\x00", " ")
		if !strings.HasPrefix(title, "nginx: worker process") || strings.Contains(title, "is shutting down") {
			continue
		}
		if t, ok := startOf(pid); ok && t.After(newest) {
			newest = t
		}
	}
	if !newest.IsZero() {
		return newest, true
	}
	return startOf(master)
}

func ppidOf(pid int) int {
	for _, l := range strings.Split(procFile(pid, "status"), "\n") {
		if v, ok := strings.CutPrefix(l, "PPid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return -1
}

// startOf is when a process started on the wall clock: the boot time plus its
// start in clock ticks since boot (field 22 of /proc/<pid>/stat), at the
// 100 ticks a second Linux reports to every architecture.
func startOf(pid int) (time.Time, bool) {
	stat := procFile(pid, "stat")
	i := strings.LastIndexByte(stat, ')') // the command name may hold spaces
	if i < 0 {
		return time.Time{}, false
	}
	f := strings.Fields(stat[i+1:])
	if len(f) < 20 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	boot, _ := os.ReadFile("/proc/stat")
	for _, l := range strings.Split(string(boot), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			if boot, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(boot, 0).Add(time.Duration(ticks) * time.Second / 100), true
			}
		}
	}
	return time.Time{}, false
}

// changedSince lists the files of the configuration modified after the
// master last loaded it, nil when that moment is unknown.
func changedSince(in instance) []string {
	at, ok := loadedAt(in.PID)
	if !ok {
		return nil
	}
	return changedAfter(in.ConfigPath, at)
}

// changedAfter lists the files config includes, itself first, modified after
// at. An include whose pattern now matches a new file lists that file too.
func changedAfter(config string, at time.Time) []string {
	payload, err := crossplane.Parse(config, &crossplane.ParseOptions{})
	if err != nil {
		return nil
	}
	var out []string
	for _, c := range payload.Config {
		if fi, err := os.Stat(c.File); err == nil && fi.ModTime().After(at.Add(clockSlack)) {
			out = append(out, c.File)
		}
	}
	return out
}
