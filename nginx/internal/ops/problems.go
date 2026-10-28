package ops

import (
	"fmt"
	"os"
	"strings"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// pathProblems words what keeps a file from being replaced safely
// (hostfile.Problems). Discovery does not suggest a certificate with any, and
// deploy refuses one.
func pathProblems(path string) []l10n.Text {
	var out []l10n.Text
	for _, pr := range hostfile.Problems(path) {
		switch pr.Kind {
		case hostfile.ACMEManaged:
			out = append(out, T("nginx.problem.acme_managed",
				"`{path}` is under `{dir}`, which another ACME client manages, and the two would overwrite each other",
				"path", pr.Path, "dir", pr.Dir))
		case hostfile.HardLink:
			out = append(out, T("nginx.problem.hard_link",
				"`{path}` has {links} hard links, and replacing it would leave the other names with the previous content",
				"path", pr.Path, "links", pr.Links))
		case hostfile.ImmutableFile:
			out = append(out, T("nginx.problem.immutable",
				"`{path}` is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced", "path", pr.Path))
		case hostfile.Unsafe:
			out = append(out, T("nginx.problem.unsafe_path",
				"`{path}` cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}",
				"path", pr.Path, "reason", pr.Reason))
		}
	}
	return out
}

// problemsOf is everything that keeps a certificate from being suggested: what
// keeps its file or its key's from being replaced safely, a key protected by a
// passphrase (nginx's ssl_password_file), which a Deployment would replace
// with an unprotected one, and a place it is served from that a Deployment
// could not check (reachProblems).
func problemsOf(c Certificate, servers []nginxServer) []l10n.Text {
	out := pathProblems(c.Path)
	if c.Key != "" {
		out = append(out, pathProblems(c.Key)...)
		if b, err := os.ReadFile(c.Key); err == nil && pemfile.EncryptedKey(b) {
			out = append(out, T("nginx.problem.encrypted_key",
				"its key `{key}` is protected by a passphrase, and a Deployment cannot keep that protection", "key", c.Key))
		}
	}
	if servers != nil && len(c.Refs) > 0 {
		out = append(out, reachProblems(servers, c.Path, fmt.Sprintf("%s:%d", c.Refs[0].File, c.Refs[0].Line))...)
	}
	return out
}

// notSuggested is one warning naming a certificate and every problem that
// keeps it from being suggested.
func notSuggested(path string, probs []l10n.Text) l10n.Text {
	return perLanguage(func(p l10n.Printer) string {
		parts := make([]string, len(probs))
		for i, pr := range probs {
			parts[i] = pr.In(p.Language())
		}
		return p.T("nginx.warning.not_suggested", "`{path}` is not suggested: {problems}.",
			"path", path, "problems", strings.Join(parts, "; "))
	})
}
