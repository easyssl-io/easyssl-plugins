package ops

import (
	"bufio"
	"os"
	"strings"
)

// Where a directive's argument is written. httpd's own dump (DUMP_CONFIG)
// gives each directive's file and line but its arguments with every ${VAR}
// expanded and quotes removed, so what a reference says is written there, and
// what relocate replaces, is read back from the file itself.

// argAt finds, on one line of a configuration file, the directive name (in
// any case, as httpd matches it) and its first argument: the argument as
// written, without its quotes, and the byte span it covers, quotes included.
// httpd reads one directive per line, its first word the name and a quoted
// argument ending at the next unescaped quote of the same kind
// (ap_getword_conf).
func argAt(line, name string) (value string, start, end int, ok bool) {
	i := skipBlank(line, 0)
	j := i
	for j < len(line) && line[j] != ' ' && line[j] != '\t' {
		j++
	}
	if !strings.EqualFold(line[i:j], name) {
		return "", 0, 0, false
	}
	start = skipBlank(line, j)
	if start == j || start >= len(line) {
		return "", 0, 0, false
	}
	if q := line[start]; q == '"' || q == '\'' {
		var b strings.Builder
		for k := start + 1; k < len(line); k++ {
			switch {
			case line[k] == '\\' && k+1 < len(line) && line[k+1] == q:
				b.WriteByte(q)
				k++
			case line[k] == q:
				return b.String(), start, k + 1, true
			default:
				b.WriteByte(line[k])
			}
		}
		return "", 0, 0, false // an unterminated quote
	}
	end = start
	for end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != '\r' {
		end++
	}
	return line[start:end], start, end, true
}

func skipBlank(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// lineOf is line n, counted from 1, of a file, without its line ending.
func lineOf(path string, n int) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for i := 1; sc.Scan(); i++ {
		if i == n {
			return sc.Text(), true
		}
	}
	return "", false
}

// asWritten is a directive's first argument as its file writes it, or as
// httpd reported it when the file's line does not hold that directive (a
// line continued with a backslash, a file gone since).
func asWritten(d directive, name string) string {
	if l, ok := lineOf(d.file, d.line); ok {
		if v, _, _, ok := argAt(l, name); ok {
			return v
		}
	}
	return d.args[0]
}
