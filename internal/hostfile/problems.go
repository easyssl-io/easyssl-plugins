package hostfile

import (
	"bytes"
	"errors"
	"os"
	"strings"
)

// ProblemKind is one reason a file cannot be replaced safely.
type ProblemKind int

const (
	// HardLink is a file with Links names, the others of which a replacement
	// would leave with the previous content.
	HardLink ProblemKind = iota + 1
	// ImmutableFile is a file chattr made immutable or append-only.
	ImmutableFile
	// Unsafe is a path a user other than its owner could redirect; Reason says
	// how.
	Unsafe
)

// Problem is why a file cannot be replaced safely, as data a Plugin words in
// its own catalog.
type Problem struct {
	Kind   ProblemKind
	Path   string
	Links  uint64
	Reason string
}

// Problems is what keeps a file from being replaced safely, for discovery to
// warn about before anyone accepts the suggestion, and for a Deployment to
// refuse on. A file another ACME client manages is not one of them: the Agent
// knows those clients and refuses such a path before running any Plugin, so
// the rule lives in one place.
func Problems(path string) []Problem {
	var out []Problem
	if m, err := MetaOf(path); err == nil {
		if m.Nlink > 1 {
			out = append(out, Problem{Kind: HardLink, Path: path, Links: m.Nlink})
		}
		if Immutable(path) {
			out = append(out, Problem{Kind: ImmutableFile, Path: path})
		}
	}
	if _, err := WriterFor(path); errors.Is(err, ErrUnsafe) {
		out = append(out, Problem{Kind: Unsafe, Path: path, Reason: strings.TrimPrefix(err.Error(), ErrUnsafe.Error()+": ")})
	}
	return out
}

// SameContent reports whether every path holds identical bytes: one key in
// several files, which a renewal writing only one of them would split. A key
// is a few kilobytes, so the files are compared rather than hashed.
func SameContent(paths []string) bool {
	if len(paths) < 2 {
		return true
	}
	first, err := os.ReadFile(paths[0])
	if err != nil {
		return false
	}
	for _, p := range paths[1:] {
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(b, first) {
			return false
		}
	}
	return true
}
