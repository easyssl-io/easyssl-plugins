package hostfile

import (
	"errors"
	"strings"
)

// ProblemKind is one reason a file cannot be replaced safely.
type ProblemKind int

const (
	// ACMEManaged is a file under a directory another ACME client manages,
	// which rewrites it on its own schedule, so the two would overwrite each
	// other. Dir names that directory.
	ACMEManaged ProblemKind = iota + 1
	// HardLink is a file with Links names, the others of which a replacement
	// would leave with the previous content.
	HardLink
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
	Dir    string
	Links  uint64
	Reason string
}

// acmeDirs are where other ACME clients keep what they manage.
var acmeDirs = []string{"/etc/letsencrypt/", "/etc/dehydrated/", "/var/lib/dehydrated/", "/.acme.sh/", "/var/lib/acme/"}

// Problems is what keeps a file from being replaced safely, for discovery to
// warn about before anyone accepts the suggestion, and for a Deployment to
// refuse on.
func Problems(path string) []Problem {
	var out []Problem
	for _, d := range acmeDirs {
		if strings.Contains(path, d) {
			out = append(out, Problem{Kind: ACMEManaged, Path: path, Dir: strings.Trim(d, "/")})
			break
		}
	}
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
