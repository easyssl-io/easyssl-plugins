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
	"syscall"
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

// Relocate points nginx's configuration at other files: in each reference the
// request confirms, it replaces the path as written with the one its move
// names, tests every instance that reads a changed file, reloads it, and
// checks that the reload took. It changes nothing unless the references its
// own reading of the configuration finds for the moves are exactly the
// confirmed ones, and puts every file back when any step fails.
func Relocate(ctx context.Context, req RelocateRequest, stdout, stderr io.Writer) error {
	p := catalog.In(hostLanguage())
	fmt.Fprintf(stdout, "%s %s · relocate\n", Name, buildversion.Version)
	found, err := scan()
	if err != nil {
		fmt.Fprintln(stdout, textOf(err).In(p.Language()))
		return errFailed
	}
	return relocate(ctx, p, req, found, stdout, stderr)
}

// relocate is Relocate on instances already found, so the tests run it on
// configurations without a running nginx.
func relocate(ctx context.Context, p l10n.Printer, req RelocateRequest, found []instance, stdout, stderr io.Writer) error {
	say := func(s string) { fmt.Fprintln(stdout, s) }
	to := map[string]string{}
	for _, m := range req.Moves {
		if prev, ok := to[m.From]; ok && prev != m.To {
			say(p.T("nginx.relocate.two_destinations", "Nothing was changed: `{from}` is moved to both `{a}` and `{b}`.",
				"from", m.From, "a", prev, "b", m.To))
			return errFailed
		}
		if why := destinationProblem(p, m.To); why != "" {
			say(p.T("nginx.relocate.bad_destination", "Nothing was changed: `{to}` cannot be written into the configuration: {reason}.",
				"to", m.To, "reason", why))
			return errFailed
		}
		to[m.From] = m.To
	}

	// What this Plugin's reading of the configuration finds, the same way
	// discovery reads it, and which masters read each reference.
	sort.Slice(found, func(i, j int) bool { return found[i].PID < found[j].PID })
	readers := map[plugincontract.Reference][]*instance{}
	var matched []plugincontract.Reference
	for i := range found {
		in := &found[i]
		if in.CertsErr != nil {
			continue
		}
		refs, _ := filesOnly(in.Certs)
		for _, r := range referencesOf(refs) {
			if _, ok := to[r.Value]; !ok {
				continue
			}
			if readers[r] == nil {
				matched = append(matched, r)
			}
			readers[r] = append(readers[r], in)
		}
	}
	missing, extra := relocation.Diff(req.References, matched)
	if len(missing) > 0 || len(extra) > 0 {
		say(p.T("nginx.relocate.mismatch",
			"Nothing was changed: the configuration does not name these paths where the confirmed list says. Run the command again to see it as it is now."))
		for _, r := range missing {
			say(p.T("nginx.relocate.mismatch.missing", "- confirmed, not found: `{at}` `{setting} {value}`",
				"at", fmt.Sprintf("%s:%d", r.File, r.Line), "setting", r.Setting, "value", r.Value))
		}
		for _, r := range extra {
			say(p.T("nginx.relocate.mismatch.extra", "- found, not confirmed: `{at}` `{setting} {value}`",
				"at", fmt.Sprintf("%s:%d", r.File, r.Line), "setting", r.Setting, "value", r.Value))
		}
		return errFailed
	}
	if len(matched) == 0 {
		say(p.T("nginx.relocate.nothing", "Nothing to change: no configuration line names these paths."))
		return nil
	}

	// Every master that reads a changed line, each once.
	var masters []*instance
	seen := map[int]bool{}
	for _, r := range matched {
		for _, in := range readers[r] {
			if !seen[in.PID] {
				seen[in.PID] = true
				masters = append(masters, in)
			}
		}
	}
	sort.Slice(masters, func(i, j int) bool { return masters[i].PID < masters[j].PID })
	for _, in := range masters {
		if len(in.Changed) > 0 {
			say(p.T("nginx.relocate.config_changed",
				"Nothing was changed: {problem} Reload nginx once those edits are ready, then run this again.",
				"problem", changedProblem(*in).In(p.Language())))
			return errFailed
		}
		if in.Signal {
			if err := in.guard(); err != nil {
				say(p.T("nginx.relocate.guard", "Nothing was changed, because the reload would not reach nginx (`pid {pid}`): {error}",
					"pid", in.PID, "error", err))
				return errFailed
			}
		}
	}

	changes, err := edits(matched, to, relocation.Note(req.Note))
	if err != nil {
		say(p.T("nginx.relocate.not_found", "Nothing was changed: {error}. Run the command again to see the configuration as it is now.", "error", err))
		return errFailed
	}
	written, err := hostfile.WriteAll(WriteFileFlag, changes)
	if err != nil {
		say(p.T("nginx.relocate.write_failed", "Nothing was changed, because a configuration file could not be written: {error}", "error", err))
		return errFailed
	}
	for _, r := range matched {
		say(p.T("nginx.relocate.changed", "`{at}`: `{from}` → `{to}`", "at", fmt.Sprintf("%s:%d", r.File, r.Line), "from", r.Value, "to", to[r.Value]))
	}

	// undo puts every file back, reloads the masters already reloaded with
	// them, and says what failed and that the original configuration is back.
	undo := func(reloaded []*instance, what string) error {
		if err := written.Revert(); err != nil {
			say(p.T("nginx.relocate.revert_failed", "{what} Putting the original configuration back failed too: {error}", "what", what, "error", err))
			return errFailed
		}
		for _, in := range reloaded {
			if err := reloadInstance(ctx, in, stdout, stderr); err != nil {
				say(p.T("nginx.relocate.rereload_failed",
					"{what} The original configuration is back on disk, but reloading nginx (`pid {pid}`) with it failed: {error}",
					"what", what, "pid", in.PID, "error", err))
				return errFailed
			}
		}
		say(p.T("nginx.relocate.reverted", "{what} The original configuration is back.", "what", what))
		return errFailed
	}

	for _, in := range masters {
		fmt.Fprintf(stdout, "$ %s\n", in.Test)
		if err := runScript(ctx, in.Test, in.Cred, stdout, stderr); err != nil {
			return undo(nil, p.T("nginx.relocate.test_failed", "The test command `{command}` {exit}, so nothing was reloaded.",
				"command", in.Test, "exit", describeExit(err)))
		}
	}
	var reloaded []*instance
	for _, in := range masters {
		mark := markReload(*in)
		err := reloadInstance(ctx, in, stdout, stderr)
		reloaded = append(reloaded, in)
		if err == nil {
			err = confirmReload(*in, mark)
		}
		if err != nil {
			return undo(reloaded, p.T("nginx.relocate.reload_failed", "Reloading nginx (`pid {pid}`) failed: {error}.",
				"pid", in.PID, "error", wordReload(p, err)))
		}
	}
	fmt.Fprintln(stdout, p.N("nginx.relocate.done", len(matched),
		"Changed {n} line; nginx tested the configuration and reloaded it.",
		"Changed {n} lines; nginx tested the configuration and reloaded it."))
	return nil
}

// destinationProblem words why a path cannot be written into the
// configuration, "" when it can.
func destinationProblem(p l10n.Printer, to string) string {
	switch relocation.Check(to) {
	case relocation.NotAbsolute:
		return p.T("nginx.relocate.not_absolute", "it is not an absolute path")
	case relocation.Missing:
		return p.T("nginx.relocate.missing", "no file exists there")
	case relocation.NotRegular:
		return p.T("nginx.relocate.not_regular", "it is not a regular file")
	case relocation.Unquotable:
		return p.T("nginx.relocate.unquotable", "it holds a quote, a backslash, a `$` or a control character, which nginx reads as syntax")
	}
	return ""
}

// edits finds each reference's argument in its file and replaces it, keeping
// how it was quoted, and leaves note on each line it changes (noteEdit). A
// file is read and written once, through its symlinks (relocation.Real),
// however many references it holds.
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
		toks := lex(old)
		var es []relocation.Edit
		noted := map[int]bool{}
		for _, r := range byFile[f] {
			n := 0
			for i := range toks {
				if !statementStart(toks, i) || toks[i].quoted || toks[i].value != r.Setting || toks[i].line != r.Line ||
					i+1 >= len(toks) || special(toks[i+1]) || toks[i+1].value != r.Value {
					continue
				}
				a := toks[i+1]
				es = append(es, relocation.Edit{Start: a.start, End: a.end, Text: quoted(to[r.Value], old[a.start])})
				if note != "" && !noted[a.line] {
					noted[a.line] = true
					es = append(es, noteEdit(old, toks, a, note))
				}
				n++
			}
			if n == 0 {
				return nil, fmt.Errorf("`%s:%d` no longer holds `%s %s`", r.File, r.Line, r.Setting, r.Value)
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

// noteEdit appends note to the end of the line holding the argument a: after
// the comment already there, as certbot's nginx plugin leaves "# managed by
// Certbot", joined with " - ", or as a comment of its own. The comment found
// is the text after the line's last token, which the lexer skipped, starting
// with `#`.
func noteEdit(b []byte, toks []token, a token, note string) relocation.Edit {
	lineStart := strings.LastIndexByte(string(b[:a.start]), '\n') + 1
	lineEnd := len(b)
	if i := strings.IndexByte(string(b[a.end:]), '\n'); i >= 0 {
		lineEnd = a.end + i
	}
	last := a.end
	for _, t := range toks {
		if t.start >= lineStart && t.start < lineEnd && t.end > last {
			last = t.end
		}
	}
	at := lineEnd
	for at > last && (b[at-1] == ' ' || b[at-1] == '\t' || b[at-1] == '\r') {
		at--
	}
	text := " # " + note
	if strings.HasPrefix(strings.TrimLeft(string(b[last:at]), " \t"), "#") {
		text = " - " + note
	}
	return relocation.Edit{Start: at, End: at, Text: text}
}

// quoted is a path as an nginx argument replacing one that began with first:
// in the same quotes when it was quoted, else bare unless something in it
// would end the argument (relocation.Check has already refused quotes,
// backslashes and `$`).
func quoted(path string, first byte) string {
	if first == '"' || first == '\'' {
		return string(first) + path + string(first)
	}
	if strings.ContainsAny(path, " \t;{}#") {
		return `"` + path + `"`
	}
	return path
}

// token is one word of an nginx configuration as its lexer reads it: value
// is the word without its quotes, as crossplane reports an argument, and
// start and end are its bytes in the file, quotes included.
type token struct {
	value      string
	line       int
	start, end int
	quoted     bool
}

func special(t token) bool {
	return !t.quoted && (t.value == ";" || t.value == "{" || t.value == "}")
}

// statementStart is a token that begins a directive: the first, or one right
// after `;`, `{` or `}`.
func statementStart(toks []token, i int) bool {
	return i == 0 || special(toks[i-1])
}

// lex splits an nginx configuration the way crossplane does, which is the
// parser discovery read it with, so a reference's line and value find the
// same token here: a `#` starting a word comments to the end of the line,
// `;`, `{` and `}` are tokens of their own, a quoted word runs to the same
// unescaped quote and loses `\` before that quote, and elsewhere a backslash
// keeps the character after it in the word.
func lex(b []byte) []token {
	var out []token
	line := 1
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' }
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			line++
			i++
		case space(c):
			i++
		case c == '#':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			out = append(out, token{value: string(c), line: line, start: i, end: i + 1})
			i++
		case c == '"' || c == '\'':
			t := token{line: line, start: i, quoted: true}
			var v []byte
			for i++; i < len(b); i++ {
				if b[i] == '\\' && i+1 < len(b) {
					if b[i+1] == c {
						v = append(v, c)
					} else {
						v = append(v, b[i], b[i+1])
					}
					if b[i+1] == '\n' {
						line++
					}
					i++
					continue
				}
				if b[i] == c {
					i++
					break
				}
				if b[i] == '\n' {
					line++
				}
				v = append(v, b[i])
			}
			t.value, t.end = string(v), i
			out = append(out, t)
		default:
			t := token{line: line, start: i}
			var v []byte
			for i < len(b) {
				c := b[i]
				if c == '\\' && i+1 < len(b) {
					v = append(v, b[i], b[i+1])
					i += 2
					continue
				}
				if c == '{' && len(v) > 0 && v[len(v)-1] == '$' {
					for i < len(b) && b[i] != '}' && !space(b[i]) {
						v = append(v, b[i])
						i++
					}
					if i < len(b) && b[i] == '}' {
						v = append(v, '}')
						i++
					}
					continue
				}
				if space(c) || c == ';' || c == '{' || c == '}' {
					break
				}
				v = append(v, c)
				i++
			}
			t.value, t.end = string(v), i
			out = append(out, t)
		}
	}
	return out
}

// reloadInstance runs a master's reload command after its guard, as deploy
// does: this Plugin's own signal as the master's user, a service manager's
// reload as root.
func reloadInstance(ctx context.Context, in *instance, stdout, stderr io.Writer) error {
	var as *syscall.Credential
	if in.Signal {
		if err := in.guard(); err != nil {
			return err
		}
		as = in.Cred
	}
	fmt.Fprintf(stdout, "$ %s\n", in.Reload)
	if err := runScript(ctx, in.Reload, as, stdout, stderr); err != nil {
		return fmt.Errorf("the reload command %s", describeExit(err))
	}
	return nil
}

// reloadMark is what a master looked like right before its reload: where its
// error log ended and which workers it ran.
type reloadMark struct {
	logs    map[string]int64
	workers map[int]bool
}

func markReload(in instance) reloadMark {
	m := reloadMark{logs: map[string]int64{}, workers: map[int]bool{}}
	if l := errorLogOf(in); l != "" {
		m.logs = logMarks([]string{l})
	}
	for _, w := range workersOf(in.PID) {
		m.workers[w] = true
	}
	return m
}

// workersOf is the pids of a master's workers that are not shutting down.
func workersOf(master int) []int {
	var out []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || ppidOf(pid) != master {
			continue
		}
		title := strings.ReplaceAll(procFile(pid, "cmdline"), "\x00", " ")
		if strings.HasPrefix(title, "nginx: worker process") && !strings.Contains(title, "is shutting down") {
			out = append(out, pid)
		}
	}
	return out
}

// reloadWait bounds how long confirmReload waits for nginx to apply a reload.
const reloadWait = 10 * time.Second

// notApplied is why a reload did not take: the master is gone, it logged
// `[emerg]` (line), or it started no new worker within reloadWait.
type notApplied struct {
	gone bool
	line string
}

func (e notApplied) Error() string {
	switch {
	case e.gone:
		return "nginx is no longer running"
	case e.line != "":
		return "nginx did not apply the reload: " + e.line
	}
	return "nginx started no new worker within " + reloadWait.String()
}

// wordReload words a reload failure in the reader's language when this
// Plugin found it, and as produced otherwise.
func wordReload(p l10n.Printer, err error) string {
	var na notApplied
	if !errors.As(err, &na) {
		return err.Error()
	}
	switch {
	case na.gone:
		return p.T("nginx.relocate.gone", "nginx is no longer running")
	case na.line != "":
		return p.T("nginx.relocate.emerg", "nginx did not apply it: {line}", "line", na.line)
	}
	return p.T("nginx.relocate.no_workers", "nginx started no new worker within {seconds} seconds", "seconds", int(reloadWait/time.Second))
}

// confirmReload waits until the master applied its reload: nginx applies one
// after the command returns, starting new workers when it succeeds and
// logging `[emerg]` and keeping the old ones when it fails. A variable so the
// tests, which run no nginx, can stand in for it.
var confirmReload = func(in instance, m reloadMark) error {
	deadline := time.Now().Add(reloadWait)
	for {
		if exeOf(in.PID) != in.Exe {
			return notApplied{gone: true}
		}
		if e := emergSince(m.logs); len(e) > 0 {
			return notApplied{line: e[0]}
		}
		for _, w := range workersOf(in.PID) {
			if !m.workers[w] {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return notApplied{}
		}
		time.Sleep(200 * time.Millisecond)
	}
}
