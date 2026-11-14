package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-plugins/internal/buildversion"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/relocation"
)

// errFailed is a relocate that changed nothing, or put back what it changed:
// what happened is on stdout, worded for the person running the Agent.
var errFailed = errors.New("relocate failed; stdout says why")

// Relocate points Apache's configuration at other files: in each reference
// the request confirms, it replaces the path as written with the one its move
// names, tests every instance that loads a changed file as the instance,
// reloads it, and checks that the master survived the reload. It changes
// nothing unless the references its own reading of the configuration finds
// for the moves are exactly the confirmed ones, and puts every file back when
// any step fails, starting a master the reload stopped again.
func Relocate(ctx context.Context, req RelocateRequest, stdout, stderr io.Writer) error {
	p := catalog.In(hostLanguage())
	fmt.Fprintf(stdout, "%s %s · relocate\n", Name, buildversion.Version)
	masters, err := scanMasters()
	if err != nil {
		fmt.Fprintln(stdout, textOf(err).In(p.Language()))
		return errFailed
	}
	return relocate(ctx, p, req, masters, readConfig, stdout)
}

// relocate is Relocate on masters already found, with their configuration
// read through read, so the tests run it on captured configurations.
func relocate(ctx context.Context, p l10n.Printer, req RelocateRequest, masters []*master, read configReader, stdout io.Writer) error {
	say := func(s string) { fmt.Fprintln(stdout, s) }
	to := map[string]string{}
	for _, m := range req.Moves {
		if prev, ok := to[m.From]; ok && prev != m.To {
			say(p.T("apache.relocate.two_destinations", "Nothing was changed: `{from}` is moved to both `{a}` and `{b}`.",
				"from", m.From, "a", prev, "b", m.To))
			return errFailed
		}
		if why := destinationProblem(p, m.To); why != "" {
			say(p.T("apache.relocate.bad_destination", "Nothing was changed: `{to}` cannot be written into the configuration: {reason}.",
				"to", m.To, "reason", why))
			return errFailed
		}
		to[m.From] = m.To
	}

	// What this Plugin's reading of the configuration finds, the same way
	// discovery reads it, and which masters load each reference.
	sv := surveyOf(masters, read)
	readers := map[plugincontract.Reference][]*master{}
	var matched []plugincontract.Reference
	for _, f := range sv.files {
		for _, l := range f.locs {
			for _, r := range referencesOf([]*location{l}) {
				if _, ok := to[r.Value]; !ok {
					continue
				}
				if readers[r] == nil {
					matched = append(matched, r)
				}
				readers[r] = append(readers[r], l.m)
			}
		}
	}
	missing, extra := relocation.Diff(req.References, matched)
	if len(missing) > 0 || len(extra) > 0 {
		say(p.T("apache.relocate.mismatch",
			"Nothing was changed: the configuration does not name these paths where the confirmed list says. Run the command again to see it as it is now."))
		for _, r := range missing {
			say(p.T("apache.relocate.mismatch.missing", "- confirmed, not found: `{at}` `{setting} {value}`",
				"at", fmt.Sprintf("%s:%d", r.File, r.Line), "setting", r.Setting, "value", r.Value))
		}
		for _, r := range extra {
			say(p.T("apache.relocate.mismatch.extra", "- found, not confirmed: `{at}` `{setting} {value}`",
				"at", fmt.Sprintf("%s:%d", r.File, r.Line), "setting", r.Setting, "value", r.Value))
		}
		return errFailed
	}
	if len(matched) == 0 {
		say(p.T("apache.relocate.nothing", "Nothing to change: no configuration line names these paths."))
		return nil
	}

	// Every master that loads a changed line, each once.
	var affected []*master
	seen := map[int]bool{}
	for _, r := range matched {
		for _, m := range readers[r] {
			if !seen[m.PID] {
				seen[m.PID] = true
				affected = append(affected, m)
			}
		}
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].PID < affected[j].PID })
	for _, m := range affected {
		if files := sv.changed[m]; len(files) > 0 {
			say(p.T("apache.relocate.config_changed",
				"Nothing was changed: `{files}` changed since Apache (`pid {pid}`) last loaded its configuration, so a reload would also apply those edits. Reload Apache once they are ready, then run this again.",
				"files", strings.Join(files, "`, `"), "pid", m.PID))
			return errFailed
		}
		if m.Graceful {
			if err := m.guard(); err != nil {
				say(p.T("apache.relocate.guard", "Nothing was changed, because the reload would not reach Apache (`pid {pid}`): {error}",
					"pid", m.PID, "error", err))
				return errFailed
			}
		}
	}

	changes, err := edits(matched, to, relocation.Note(req.Note))
	if err != nil {
		say(p.T("apache.relocate.not_found", "Nothing was changed: {error}. Run the command again to see the configuration as it is now.", "error", err))
		return errFailed
	}
	written, err := hostfile.WriteAll(WriteFileFlag, changes)
	if err != nil {
		say(p.T("apache.relocate.write_failed", "Nothing was changed, because a configuration file could not be written: {error}", "error", err))
		return errFailed
	}
	for _, r := range matched {
		say(p.T("apache.relocate.changed", "`{at}`: `{from}` → `{to}`", "at", fmt.Sprintf("%s:%d", r.File, r.Line), "from", r.Value, "to", to[r.Value]))
	}

	// undo puts every file back, reloads the masters already reloaded, or
	// starts one the reload stopped, and says what failed and that the
	// original configuration is back.
	undo := func(reloaded []*master, what string) error {
		if err := written.Revert(); err != nil {
			say(p.T("apache.relocate.revert_failed", "{what} Putting the original configuration back failed too: {error}", "what", what, "error", err))
			return errFailed
		}
		for _, m := range reloaded {
			if !stillRunning(m) {
				say(what + " " + startAgain(ctx, p, m, sv.cfgs[m], stdout))
				return errFailed
			}
			if err := reloadMaster(ctx, m, stdout); err != nil {
				say(p.T("apache.relocate.rereload_failed",
					"{what} The original configuration is back on disk, but reloading Apache (`pid {pid}`) with it failed: {error}",
					"what", what, "pid", m.PID, "error", err))
				return errFailed
			}
		}
		say(p.T("apache.relocate.reverted", "{what} The original configuration is back.", "what", what))
		return errFailed
	}

	for _, m := range affected {
		if err := testMaster(ctx, m, stdout); err != nil {
			return undo(nil, p.T("apache.relocate.test_failed", "The test command `{command}` {exit}, so nothing was reloaded.",
				"command", m.testCommand(), "exit", describeExit(err)))
		}
	}
	var reloaded []*master
	for _, m := range affected {
		before := childrenOf(m)
		markErrorLog(m)
		err := reloadMaster(ctx, m, stdout)
		reloaded = append(reloaded, m)
		if err == nil {
			err = confirmReload(m, before)
		}
		if err != nil {
			for _, l := range emergLines(m) {
				fmt.Fprintf(stdout, "error log: %s\n", l)
			}
			why := err.Error()
			if errors.Is(err, errStopped) {
				why = p.T("apache.relocate.stopped", "Apache stopped")
			}
			return undo(reloaded, p.T("apache.relocate.reload_failed", "Reloading Apache (`pid {pid}`) failed: {error}.",
				"pid", m.PID, "error", why))
		}
	}
	say(p.N("apache.relocate.done", len(matched),
		"Changed {n} line; Apache tested the configuration and reloaded it.",
		"Changed {n} lines; Apache tested the configuration and reloaded it."))
	return nil
}

// startAgain starts a master the reload stopped, now that its original
// configuration is back, and words how that went.
func startAgain(ctx context.Context, p l10n.Printer, m *master, s *serverCfg, stdout io.Writer) string {
	waitGone(m)
	how, err := restart(ctx, m, s, stdout)
	if err != nil {
		return p.T("apache.relocate.restart_failed",
			"The original configuration is back, but Apache could not be started again (`{how}`): {error}", "how", how, "error", err)
	}
	if back := waitBack(m); back != 0 {
		return p.T("apache.relocate.restarted",
			"The original configuration is back, and Apache was started again (`{how}`, `pid {pid}`).", "how", how, "pid", back)
	}
	return p.T("apache.relocate.not_back",
		"The original configuration is back, but Apache is not running {seconds} seconds after starting it again (`{how}`).",
		"seconds", int(restartWait/time.Second), "how", how)
}

// destinationProblem words why a path cannot be written into the
// configuration, "" when it can.
func destinationProblem(p l10n.Printer, to string) string {
	switch relocation.Check(to) {
	case relocation.NotAbsolute:
		return p.T("apache.relocate.not_absolute", "it is not an absolute path")
	case relocation.Missing:
		return p.T("apache.relocate.missing", "no file exists there")
	case relocation.NotRegular:
		return p.T("apache.relocate.not_regular", "it is not a regular file")
	case relocation.Unquotable:
		return p.T("apache.relocate.unquotable", "it holds a quote, a backslash, a `$` or a control character, which Apache reads as syntax")
	}
	return ""
}

// edits finds each reference's argument at its line (argAt) and replaces it,
// keeping how it was quoted, and leaves note as a comment line above each line
// it changes (noteLine). A file is read and written once, through its
// symlinks (relocation.Real), however many references it holds.
func edits(refs []plugincontract.Reference, to map[string]string, note string) ([]hostfile.Change, error) {
	byFile := map[string][]plugincontract.Reference{}
	var order []string
	for _, r := range refs {
		real, err := relocation.Real(r.File)
		if err != nil {
			return nil, err
		}
		if byFile[real] == nil {
			order = append(order, real)
		}
		byFile[real] = append(byFile[real], r)
	}
	var out []hostfile.Change
	for _, f := range order {
		old, err := hostfile.ReadSafely(f)
		if err != nil {
			return nil, err
		}
		starts := []int{0} // where each line begins, line n at starts[n-1]
		for i, c := range old {
			if c == '\n' {
				starts = append(starts, i+1)
			}
		}
		var es []relocation.Edit
		noted := map[int]bool{}
		for _, r := range byFile[f] {
			var v string
			var a, b int
			ok := r.Line >= 1 && r.Line <= len(starts)
			if ok {
				line := string(old[starts[r.Line-1]:])
				line, _, _ = strings.Cut(line, "\n")
				v, a, b, ok = argAt(line, r.Setting)
			}
			if !ok || v != r.Value {
				return nil, fmt.Errorf("`%s:%d` no longer holds `%s %s`", r.File, r.Line, r.Setting, r.Value)
			}
			at := starts[r.Line-1]
			es = append(es, relocation.Edit{Start: at + a, End: at + b, Text: quoted(to[r.Value], old[at+a])})
			if note != "" && !noted[r.Line] {
				noted[r.Line] = true
				es = append(es, noteLine(old, at, note))
			}
		}
		updated, err := relocation.Apply(old, es)
		if err != nil {
			return nil, err
		}
		out = append(out, hostfile.Change{Path: f, Old: old, New: updated})
	}
	return out, nil
}

// noteLine puts note on a line of its own above the line starting at at,
// indented as that line is and ending as it does. Apache reads `#` as a
// comment only at the start of a line, so a note cannot follow the directive
// as it does in nginx.
func noteLine(b []byte, at int, note string) relocation.Edit {
	indent := at
	for indent < len(b) && (b[indent] == ' ' || b[indent] == '\t') {
		indent++
	}
	eol := "\n"
	if i := strings.IndexByte(string(b[at:]), '\n'); i > 0 && b[at+i-1] == '\r' {
		eol = "\r\n"
	}
	return relocation.Edit{Start: at, End: at, Text: string(b[at:indent]) + "# " + note + eol}
}

// quoted is a path as an Apache argument replacing one that began with first:
// in the same quotes when it was quoted, else bare unless a blank in it would
// split it (relocation.Check has already refused quotes, backslashes and `$`).
func quoted(path string, first byte) string {
	if first == '"' || first == '\'' {
		return string(first) + path + string(first)
	}
	if strings.ContainsAny(path, " \t") {
		return `"` + path + `"`
	}
	return path
}

// childrenOf is the pids of a master's children: the processes of its current
// generation, which a graceful restart replaces once the configuration loads.
// Read from each process's parent alone: the exe link of a child running as
// another user is unreadable to root without CAP_SYS_PTRACE, as in a
// container.
func childrenOf(m *master) map[int]bool {
	out := map[int]bool{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && ppidOf(pid) == m.PID {
			out[pid] = true
		}
	}
	return out
}

// reloadWait bounds how long confirmReload waits for a master to show it
// applied a reload.
const reloadWait = 10 * time.Second

// errStopped is a master that exited during the reload, which is how httpd
// answers a configuration it cannot load.
var errStopped = errors.New("the Apache master stopped")

// The steps relocate runs against a master, variables so the tests, which run
// no Apache, can stand in for them.
var (
	// testMaster runs the master's own configuration test, as the master's
	// user and with its environment.
	testMaster = func(ctx context.Context, m *master, stdout io.Writer) error {
		fmt.Fprintf(stdout, "$ %s\n", m.testCommand())
		out, err := runSetting(ctx, m.testCommand(), m.runEnv(), m.Cred)
		io.WriteString(stdout, out)
		return err
	}
	// reloadMaster runs the reload discovery derived for the master, as
	// deploy does.
	reloadMaster = func(ctx context.Context, m *master, stdout io.Writer) error {
		return reload(ctx, m, m.reloadCommand(), stdout)
	}
	// stillRunning is whether the master runs the binary it ran.
	stillRunning = func(m *master) bool { return m.alive() }
	// confirmReload waits until the master shows it applied the reload: httpd
	// loads the configuration after the command returns, starts a new
	// generation of children when it can and exits when it cannot. A master
	// still running after reloadWait with no new child has given no sign
	// either way and is taken as applied.
	confirmReload = func(m *master, before map[int]bool) error {
		deadline := time.Now().Add(reloadWait)
		for {
			if !m.alive() {
				return errStopped
			}
			for pid := range childrenOf(m) {
				if !before[pid] {
					return nil
				}
			}
			if time.Now().After(deadline) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
)
