package ops

import (
	"io"

	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// Checking what Apache serves after the reload. The reload command returning
// says little: `-k graceful` and `systemctl reload` return once the signal is
// sent, the master loads the configuration afterwards, and when that fails it
// exits while the command has already returned 0. So every place discovery
// found the file served is asked over TLS which certificate it now presents.

// endpointsFor lists where the file is served, once each. An endpoint that
// asks for a key type (a virtual host with one certificate per type) asks for
// the new Certificate's, which deploy's key-type guard has made the one this
// file now holds.
func endpointsFor(f *certFile, alg string) []endpoint {
	var out []endpoint
	seen := map[string]bool{}
	for _, l := range f.locs {
		for _, e := range l.endpoints {
			if e.alg != "" {
				e.alg = alg
			}
			if k := e.String(); !seen[k] {
				seen[k] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// verify waits until every endpoint serves the leaf, the master staying alive,
// and says what each served.
func verify(m *master, eps []endpoint, leaf []byte, stdout io.Writer) (string, error) {
	checks := make([]tlscheck.Endpoint, len(eps))
	for i, e := range eps {
		checks[i] = e.check()
	}
	return tlscheck.Verify(m.alive, checks, leaf, stdout)
}
