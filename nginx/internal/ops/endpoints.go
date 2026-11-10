package ops

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// Where a client reaches a certificate, for deploy to ask after the reload
// whether nginx serves the new one there, and for discovery to leave out a
// certificate served somewhere that cannot be asked. A reload command returning says
// nothing about that: nginx applies the reload afterwards, and when applying
// any part of it fails, most often a `listen` it cannot bind in a file
// unrelated to this Target, it keeps serving the previous configuration.
//
// Only places this can work out with confidence are listed, since a place
// listed wrongly would fail a good Deployment and put the old files back:
//
//   - a `listen` with the `ssl` parameter, or any `listen` in a server with
//     the old `ssl on;`, but not with `proxy_protocol`, which expects a PROXY
//     header before the handshake, nor `quic`, which is UDP, nor a UNIX socket
//     or a host name;
//   - an exact address is dialed as written, and a wildcard one at loopback,
//     unless some server listens on loopback at that port explicitly, which
//     then answers loopback connections instead;
//   - the name sent is the first exact `server_name` no earlier server on that
//     address claims, or a made-up name under a `*.` wildcard, and with no
//     such name none is sent, but only when the server is that address's
//     default (`default_server`, else the first to listen there);
//   - a server holding certificates of two key types is asked for the new
//     Certificate's.

// nginxServer is one `server` block: in the http or the stream module, with its
// listens, names and the certificates it loads (its own, else those it
// inherits from the module's level).
type nginxServer struct {
	stream    bool
	at        string // file:line of the `server` directive
	listens   []listen
	names     []string
	certs     []string // resolved
	inherited bool     // certs come from the module's level
}

type listen struct {
	ip, port                   string // ip "*" or "::" for a wildcard
	ssl, def, proxy, quic, bad bool
}

// located is a directive and the file it was written in, which crossplane
// records only when it combines the files into one.
type located struct {
	d    *crossplane.Directive
	file string
}

// serversOf parses an instance's configuration into its server blocks,
// following every include in place, which collect does not need to do.
func serversOf(config string) ([]nginxServer, error) {
	payload, err := crossplane.Parse(config, &crossplane.ParseOptions{})
	if err != nil {
		return nil, err
	}
	if len(payload.Config) == 0 {
		return nil, nil
	}
	var out []nginxServer
	for _, top := range flatten(payload, payload.Config[0].Parsed, payload.Config[0].File, 0) {
		if top.d.Directive != "http" && top.d.Directive != "stream" {
			continue
		}
		module := flatten(payload, top.d.Block, top.file, 0)
		inherited := certsIn(module, config)
		for _, l := range module {
			if l.d.Directive != "server" {
				continue
			}
			s := serverOf(flatten(payload, l.d.Block, l.file, 0), top.d.Directive == "stream", inherited, config)
			s.at = fmt.Sprintf("%s:%d", l.file, l.d.Line)
			out = append(out, s)
		}
	}
	return out, nil
}

// flatten is dirs with every include replaced by what it includes, so a
// directive in a snippet counts in the context that includes it.
func flatten(p *crossplane.Payload, dirs crossplane.Directives, file string, depth int) []located {
	var out []located
	for _, d := range dirs {
		if d.Directive != "include" || depth > 16 {
			out = append(out, located{d, file})
			continue
		}
		for _, i := range d.Includes {
			if i < len(p.Config) {
				out = append(out, flatten(p, p.Config[i].Parsed, p.Config[i].File, depth+1)...)
			}
		}
	}
	return out
}

func certsIn(dirs []located, config string) []string {
	var out []string
	for _, l := range dirs {
		if l.d.Directive == "ssl_certificate" && len(l.d.Args) > 0 {
			p, _ := resolve(l.d.Args[0], config)
			out = append(out, p)
		}
	}
	return out
}

func serverOf(dirs []located, stream bool, inherited []string, config string) nginxServer {
	s := nginxServer{stream: stream, certs: certsIn(dirs, config)}
	if len(s.certs) == 0 {
		s.certs, s.inherited = inherited, true
	}
	sslOn := false
	for _, l := range dirs {
		d := l.d
		switch d.Directive {
		case "listen":
			if len(d.Args) > 0 {
				s.listens = append(s.listens, parseListen(d.Args))
			}
		case "server_name":
			s.names = append(s.names, d.Args...)
		case "ssl":
			sslOn = len(d.Args) > 0 && d.Args[0] == "on"
		}
	}
	if sslOn {
		for i := range s.listens {
			s.listens[i].ssl = true
		}
	}
	return s
}

// parseListen reads a `listen` directive's address and the parameters that
// matter here.
func parseListen(args []string) listen {
	l := listen{}
	a := args[0]
	switch {
	case strings.HasPrefix(a, "unix:"):
		l.bad = true
	case strings.HasPrefix(a, "["):
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			host, port = strings.Trim(a, "[]"), "80"
		}
		l.ip, l.port = host, port
	case strings.Contains(a, ":"):
		i := strings.LastIndex(a, ":")
		l.ip, l.port = a[:i], a[i+1:]
	case isPort(a):
		l.ip, l.port = "*", a
	default:
		l.ip, l.port = a, "80"
	}
	if l.ip != "*" && net.ParseIP(l.ip) == nil {
		l.bad = true // a host name, resolved by nginx at startup
	}
	for _, p := range args[1:] {
		switch p {
		case "ssl":
			l.ssl = true
		case "default_server", "default":
			l.def = true
		case "proxy_protocol":
			l.proxy = true
		case "quic":
			l.quic = true
		}
	}
	return l
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536
}

// key names the address a listen binds, a wildcard as "*".
func (l listen) key() string {
	ip := l.ip
	if ip == "::" {
		ip = "*6"
	}
	return ip + "|" + l.port
}

// reach is whether deploy can check what a listen serves, and if not, why.
type reach int

const (
	reachable     reach = iota
	notTLS              // no `ssl`
	viaProxy            // `proxy_protocol`
	viaQUIC             // UDP
	noAddress           // a UNIX socket or a host name
	loopbackTaken       // a wildcard whose loopback another server answers
	shadowed            // every name belongs to an earlier server there
	nameless            // no name to send, and not the address's default
)

// place is one listen of one server: how it can be checked, the endpoint
// when it can, and for a shadowed one the server that owns its names.
type place struct {
	reach reach
	ep    tlscheck.Endpoint
	by    int
}

// placesOf is every listen of every server, in order.
func placesOf(servers []nginxServer) [][]place {
	// Which server owns each name on each address, the first to name it, and
	// which server is each address's default.
	owner := map[string]int{}
	def := map[string]int{}
	explicitDef := map[string]bool{}
	loopback := map[string]bool{} // ports some server listens on at loopback explicitly
	for i, s := range servers {
		for _, l := range s.listens {
			if l.bad {
				continue
			}
			k := l.key()
			if ip := net.ParseIP(l.ip); ip != nil && ip.IsLoopback() {
				loopback[l.port] = true
			}
			if _, ok := def[k]; !ok || (l.def && !explicitDef[k]) {
				def[k] = i
				explicitDef[k] = explicitDef[k] || l.def
			}
			for _, n := range s.names {
				if _, ok := owner[k+"|"+n]; !ok {
					owner[k+"|"+n] = i
				}
			}
		}
	}
	out := make([][]place, len(servers))
	for i, s := range servers {
		for _, l := range s.listens {
			out[i] = append(out[i], placeOf(s, i, l, owner, def, loopback))
		}
	}
	return out
}

func placeOf(s nginxServer, i int, l listen, owner, def map[string]int, loopback map[string]bool) place {
	switch {
	case l.quic:
		return place{reach: viaQUIC}
	case !l.ssl:
		return place{reach: notTLS}
	case l.proxy:
		return place{reach: viaProxy}
	case l.bad:
		return place{reach: noAddress}
	}
	k := l.key()
	ip := l.ip
	switch ip {
	case "*", "::":
		if loopback[l.port] {
			return place{reach: loopbackTaken}
		}
		ip = map[string]string{"*": "127.0.0.1", "::": "::1"}[ip]
	}
	ep := tlscheck.Endpoint{IP: ip, Port: l.port}
	if s.stream {
		return place{ep: ep}
	}
	by, all := -1, len(s.names) > 0
	for _, n := range s.names {
		name := checkName(n)
		if name == "" {
			all = false
			continue
		}
		if o := owner[k+"|"+n]; o == i {
			ep.SNI = name
			return place{ep: ep}
		} else if by < 0 {
			by = o
		}
	}
	if def[k] == i {
		return place{ep: ep}
	}
	if all {
		return place{reach: shadowed, by: by}
	}
	return place{reach: nameless}
}

// endpointsFor lists where the servers serve the certificate at path, once
// each, asking for alg ("RSA", "ECDSA") where a server holds certificates of
// more than one key type.
func endpointsFor(servers []nginxServer, path, alg string) []tlscheck.Endpoint {
	var out []tlscheck.Endpoint
	seen := map[string]bool{}
	for i, ps := range placesOf(servers) {
		s := servers[i]
		if !loads(s, path) {
			continue
		}
		for _, p := range ps {
			if p.reach != reachable {
				continue
			}
			e := p.ep
			if len(s.certs) > 1 {
				e.Alg = alg
			}
			if !seen[e.String()] {
				seen[e.String()] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// reachProblems words what keeps deploy from checking, after a reload, a place
// nginx serves the certificate at path from; refAt is where the configuration
// first names it. Discovery does not suggest a certificate with any, since a
// reload nginx failed to apply there would go unnoticed.
func reachProblems(servers []nginxServer, path, refAt string) []l10n.Text {
	var out []l10n.Text
	served := false
	places := placesOf(servers)
	for i, s := range servers {
		if !loads(s, path) {
			continue
		}
		tls, ok, proxy, other, by := false, false, false, false, -1
		for _, p := range places[i] {
			switch p.reach {
			case notTLS:
				continue
			case reachable:
				ok = true
			case viaProxy:
				proxy = true
			case shadowed:
				other = true
				if by < 0 {
					by = p.by
				}
			default:
				other = true
			}
			tls = true
		}
		if !tls {
			if !s.inherited {
				out = append(out, T("nginx.problem.no_tls",
					"The server at `{at}` has no `listen` with `ssl`, so it never serves this certificate.", "at", s.at))
			}
			continue
		}
		served = true
		if proxy {
			out = append(out, T("nginx.problem.proxy_protocol",
				"The server at `{at}` expects the PROXY protocol (`proxy_protocol`), so a local connection cannot check what it serves.",
				"at", s.at))
		}
		switch {
		case ok || !other:
		case by >= 0:
			out = append(out, T("nginx.problem.shadowed",
				"No client reaches the server at `{at}`: each of its names belongs to the server at `{by}` on the same address, and it is not that address's default.",
				"at", s.at, "by", servers[by].at))
		default:
			out = append(out, T("nginx.problem.cannot_check",
				"None of the `listen` directives of the server at `{at}` gives an address and a name this Plugin can connect to, so what it serves cannot be checked after a reload.",
				"at", s.at))
		}
	}
	if !served && len(out) == 0 {
		out = append(out, T("nginx.problem.unused_module_level",
			"It is set at `{at}`, outside any server, but no server that inherits it listens with `ssl`, so nothing serves it.",
			"at", refAt))
	}
	return out
}

func loads(s nginxServer, path string) bool {
	for _, c := range s.certs {
		if c == path {
			return true
		}
	}
	return false
}

// checkName is the name to send for a server_name: an exact host name as it
// is, a made-up host under a leading `*.` wildcard, and "" for anything else
// (a regular expression, a trailing wildcard, `_`, an address).
func checkName(n string) string {
	if d, ok := strings.CutPrefix(n, "*."); ok {
		n = "easyssl-check." + d
	} else {
		n = strings.TrimPrefix(n, ".")
	}
	if n == "" || strings.ContainsAny(n, "*~$()[]{}\\^ ") || net.ParseIP(n) != nil || !strings.Contains(n, ".") && n != "localhost" {
		return ""
	}
	return strings.ToLower(n)
}
