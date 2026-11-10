// Package relocation is what the Plugins' relocate operations share: checking
// the file a configuration is to name instead, comparing the references a
// Plugin finds with the ones a person confirmed, and making replacements in a
// configuration file's bytes. Finding the replacements is each Plugin's own,
// since only it knows its configuration's syntax.
package relocation

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Problem is why a path cannot be written into a configuration.
type Problem int

const (
	// NotAbsolute is a relative path, which each server would resolve
	// against a base of its own.
	NotAbsolute Problem = iota + 1
	// Missing is a path naming nothing: the file has to exist before a
	// configuration names it, or the test fails.
	Missing
	// NotRegular is a path naming something other than a regular file.
	NotRegular
	// Unquotable is a path holding a quote, a backslash, a `$` or a control
	// character, which a configuration reads as syntax (an escape, the end of
	// a quoted argument, a variable) rather than as part of the name.
	Unquotable
)

// Check is what keeps to from being written into a configuration as a path,
// 0 for nothing.
func Check(to string) Problem {
	if !filepath.IsAbs(to) {
		return NotAbsolute
	}
	for _, r := range to {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '\\' || r == '$' || r == '`' {
			return Unquotable
		}
	}
	fi, err := os.Stat(to)
	if err != nil {
		return Missing
	}
	if !fi.Mode().IsRegular() {
		return NotRegular
	}
	return 0
}

// Diff is what want holds and got does not (missing), and what got holds and
// want does not (extra), each once and in the order first seen.
func Diff[T comparable](want, got []T) (missing, extra []T) {
	in := func(xs []T) map[T]bool {
		m := map[T]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	w, g := in(want), in(got)
	seen := map[T]bool{}
	for _, x := range want {
		if !g[x] && !seen[x] {
			seen[x] = true
			missing = append(missing, x)
		}
	}
	for _, x := range got {
		if !w[x] && !seen[x] {
			seen[x] = true
			extra = append(extra, x)
		}
	}
	return missing, extra
}

// Edit replaces the bytes [Start, End) of a file's content with Text.
type Edit struct {
	Start, End int
	Text       string
}

// Apply makes edits in content, which must lie within it and not overlap; two
// equal edits are one.
func Apply(content []byte, edits []Edit) ([]byte, error) {
	es := append([]Edit(nil), edits...)
	sort.Slice(es, func(i, j int) bool { return es[i].Start < es[j].Start })
	var out []byte
	at := 0
	for i, e := range es {
		if i > 0 && e == es[i-1] {
			continue
		}
		if e.Start < at || e.End < e.Start || e.End > len(content) {
			return nil, fmt.Errorf("relocation: edit %d:%d overlaps another or lies outside the content", e.Start, e.End)
		}
		out = append(out, content[at:e.Start]...)
		out = append(out, e.Text...)
		at = e.End
	}
	return append(out, content[at:]...), nil
}

// Real is the file a configuration names, through any symlink: an `include`
// often names a link (sites-enabled to sites-available), and replacing the
// link with a regular file would cut it away from what it links to.
func Real(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
