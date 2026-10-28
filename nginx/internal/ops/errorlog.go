package ops

import (
	"io"
	"os"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

// Quoting why nginx did not apply a reload. nginx writes the reason, one
// `[emerg]` line, to its error log after the reload command has returned, so
// deploy notes each log's size before the reload and reads what follows it.

// errorLogOf is the file a master logs errors to: the first main-level
// `error_log` naming a file, else the path the binary was compiled with. A
// relative path is relative to the master's prefix, not to the
// configuration's directory. "" when it logs somewhere else (stderr, syslog, memory).
func errorLogOf(in instance) string {
	log := in.build.errorLog
	if payload, err := crossplane.Parse(in.ConfigPath, &crossplane.ParseOptions{}); err == nil && len(payload.Config) > 0 {
		for _, l := range flatten(payload, payload.Config[0].Parsed, payload.Config[0].File, 0) {
			if l.d.Directive == "error_log" && len(l.d.Args) > 0 {
				log = l.d.Args[0]
				break
			}
		}
	}
	if log == "stderr" || strings.Contains(log, ":") {
		return ""
	}
	return under(in.Prefix, log)
}

// logMarks is each error log's size now.
func logMarks(logs []string) map[string]int64 {
	out := map[string]int64{}
	for _, l := range logs {
		if fi, err := os.Stat(l); err == nil {
			out[l] = fi.Size()
		}
	}
	return out
}

// emergSince is the distinct `[emerg]` messages the logs gained since marks,
// without their timestamp and process prefix, at most five. nginx retries a
// failed bind() five times and then logs "still could not bind()", so the
// first is the reason.
func emergSince(marks map[string]int64) []string {
	var out []string
	seen := map[string]bool{}
	for path, from := range marks {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err != nil || fi.Size() < from {
			from = 0 // rotated since
		}
		if _, err := f.Seek(from, io.SeekStart); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
			for _, l := range strings.Split(string(b), "\n") {
				if _, m, ok := strings.Cut(l, "[emerg] "); ok {
					if _, after, ok := strings.Cut(m, ": "); ok && strings.Contains(m[:len(m)-len(after)], "#") {
						m = after // "27#27: "
					}
					if m = strings.TrimSpace(m); !seen[m] {
						seen[m] = true
						out = append(out, m)
					}
				}
			}
		}
		f.Close()
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
