package ops

import (
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
)

// pathProblems words what keeps a file from being replaced safely
// (hostfile.Problems): the certificate file itself, which a reader sees named
// beside the warning, or a key, which the warning names. Discovery does not
// suggest a certificate with any, and deploy refuses one.
func pathProblems(path string, key bool) []msg {
	var out []msg
	for _, pr := range hostfile.Problems(path) {
		switch {
		case pr.Kind == hostfile.HardLink && key:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_hard_link",
					"Its key `{key}` has {links} hard links, and replacing it would leave the other names with the previous content.",
					"key", pr.Path, "links", pr.Links)
			})
		case pr.Kind == hostfile.HardLink:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.hard_link",
					"The certificate file has {links} hard links, and replacing it would leave the other names with the previous content.",
					"links", pr.Links)
			})
		case pr.Kind == hostfile.ImmutableFile && key:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_immutable", "Its key `{key}` is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced.", "key", pr.Path)
			})
		case pr.Kind == hostfile.ImmutableFile:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.immutable", "The certificate file is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced.")
			})
		case pr.Kind == hostfile.Unsafe && key:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_unsafe_path",
					"Its key `{key}` cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}.",
					"key", pr.Path, "reason", pr.Reason)
			})
		case pr.Kind == hostfile.Unsafe:
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.unsafe_path",
					"The certificate file cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}.",
					"reason", pr.Reason)
			})
		}
	}
	return out
}
