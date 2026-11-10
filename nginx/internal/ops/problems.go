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
// (hostfile.Problems): the certificate file itself, which a reader sees named
// beside the warning, or its key, which the warning names. Discovery does not
// suggest a certificate with any, and deploy refuses one.
func pathProblems(path string, key bool) []l10n.Text {
	var out []l10n.Text
	for _, pr := range hostfile.Problems(path) {
		switch {
		case pr.Kind == hostfile.HardLink && key:
			out = append(out, T("nginx.problem.key_hard_link",
				"Its key `{key}` has {links} hard links, and replacing it would leave the other names with the previous content.",
				"key", pr.Path, "links", pr.Links))
		case pr.Kind == hostfile.HardLink:
			out = append(out, T("nginx.problem.hard_link",
				"The certificate file has {links} hard links, and replacing it would leave the other names with the previous content.",
				"links", pr.Links))
		case pr.Kind == hostfile.ImmutableFile && key:
			out = append(out, T("nginx.problem.key_immutable",
				"Its key `{key}` is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced.", "key", pr.Path))
		case pr.Kind == hostfile.ImmutableFile:
			out = append(out, T("nginx.problem.immutable",
				"The certificate file is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced."))
		case pr.Kind == hostfile.Unsafe && key:
			out = append(out, T("nginx.problem.key_unsafe_path",
				"Its key `{key}` cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}.",
				"key", pr.Path, "reason", pr.Reason))
		case pr.Kind == hostfile.Unsafe:
			out = append(out, T("nginx.problem.unsafe_path",
				"The certificate file cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}.",
				"reason", pr.Reason))
		}
	}
	return out
}

// problemsOf is everything about a certificate's files and its instance that
// keeps it from being suggested: what keeps its file or its key's from being
// replaced safely, a key protected by a passphrase (nginx's
// ssl_password_file), which a Deployment would replace with an unprotected
// one, a place it is served from that a Deployment could not check
// (reachProblems), a configuration edited since nginx loaded it, and a reload
// signal that would not reach the master.
func problemsOf(c Certificate, in *instance) []l10n.Text {
	out := pathProblems(c.Path, false)
	if c.Key != "" && !notAFile(c.Key, true) {
		out = append(out, pathProblems(c.Key, true)...)
		if b, err := os.ReadFile(c.Key); err == nil && pemfile.EncryptedKey(b) {
			out = append(out, T("nginx.problem.encrypted_key",
				"Its key `{key}` is protected by a passphrase, and a Deployment cannot keep that protection.", "key", c.Key))
		}
	}
	if in == nil {
		return out
	}
	if in.Servers != nil && len(c.Refs) > 0 {
		out = append(out, reachProblems(in.Servers, c.Path, fmt.Sprintf("%s:%d", c.Refs[0].File, c.Refs[0].Line))...)
	}
	if len(in.Changed) > 0 {
		out = append(out, changedProblem(*in))
	}
	if in.Signal && in.guard() != nil {
		out = append(out, T("nginx.problem.pid_file",
			"`{pidfile}`, where its reload command `nginx -s reload` reads the pid to signal, does not name `pid {pid}`, so the reload would not reach it.",
			"pidfile", in.pidFile(), "pid", in.PID))
	}
	return out
}

// changedProblem names the files of a master's configuration edited since it
// loaded them, which a reload would also apply.
func changedProblem(in instance) l10n.Text {
	return T("nginx.problem.config_changed",
		"`{files}` changed since nginx (`pid {pid}`) last loaded its configuration, so a reload would also apply those edits.",
		"files", strings.Join(in.Changed, "`, `"), "pid", in.PID)
}

// notAFile reports a certificate or key value that is not the name of one
// file this Plugin could write. nginx's documentation of ssl_certificate and
// ssl_certificate_key lists them: a variable in the name (1.15.9), loaded per
// handshake, `data:` (1.15.10), loaded from a variable, and for a key
// `engine:` (1.7.9) and `store:` (1.29.0), loaded from OpenSSL. Written as a
// path, any of them would be a new file nothing reads, while the Deployment
// reports success.
func notAFile(value string, key bool) bool {
	if strings.Contains(value, "$") || strings.HasPrefix(value, "data:") {
		return true
	}
	return key && (strings.HasPrefix(value, "engine:") || strings.HasPrefix(value, "store:"))
}

// filesOnly drops every occurrence whose certificate is not a file
// (notAFile), with one warning each: there is no file to make a Target of. An
// occurrence whose key is not a file is kept, with that value as its key, so
// the certificate is reported with a warning saying so (warningsOf) and a
// block that also pairs it with a key file shows as a key conflict.
func filesOnly(refs []CertRef) ([]CertRef, []l10n.Text) {
	var warnings []l10n.Text
	var out []CertRef
	for _, r := range refs {
		if notAFile(r.Value, false) {
			warnings = append(warnings, T("nginx.warning.not_a_file",
				"`{value}` (`{at}`) is not the name of one file (it holds a variable, or starts with `data:`), so a Deployment has no file to write, and nothing there is reported",
				"value", shorten(r.Value), "at", fmt.Sprintf("pid %d:%s:%d", r.PID, r.File, r.Line)))
			continue
		}
		if r.KeyValue != "" && notAFile(r.KeyValue, true) {
			r.KeyResolved = r.KeyValue
		}
		out = append(out, r)
	}
	return out, warnings
}

// shorten keeps a value readable in a warning: a `data:` value is a whole
// PEM, of which the first line says enough. Anything else is kept whole.
func shorten(v string) string {
	if !strings.HasPrefix(v, "data:") {
		return v
	}
	v, _, cut := strings.Cut(v, "\n")
	if r := []rune(v); len(r) > 60 {
		v, cut = string(r[:60]), true
	}
	if cut {
		v += "…"
	}
	return v
}
