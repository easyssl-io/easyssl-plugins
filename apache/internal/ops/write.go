package ops

import (
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
)

// pathProblems words what keeps a file from being replaced safely
// (hostfile.Problems), for discovery to warn about before anyone accepts the
// suggestion.
func pathProblems(path string) []msg {
	var out []msg
	for _, pr := range hostfile.Problems(path) {
		switch pr.Kind {
		case hostfile.ACMEManaged:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.acme_managed",
					"`{path}` is under `{dir}`, which another ACME client manages, and the two would overwrite each other",
					"path", pr.Path, "dir", pr.Dir)
			})
		case hostfile.HardLink:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.hard_link",
					"`{path}` has {links} hard links, and replacing it would leave the other names with the previous content",
					"path", pr.Path, "links", pr.Links)
			})
		case hostfile.ImmutableFile:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.immutable", "`{path}` is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced", "path", pr.Path)
			})
		case hostfile.Unsafe:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.unsafe_path",
					"`{path}` cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}",
					"path", pr.Path, "reason", pr.Reason)
			})
		}
	}
	return out
}
