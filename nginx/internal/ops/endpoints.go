package ops

import (
	"net"
	"strconv"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// Where a client reaches a certificate, for deploy to ask after the reload
// whether nginx serves the new one there. A reload command returning says
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
	stream  bool
	listens []listen
	names   []string
	certs   []string // resolved
}

type listen struct {
	ip, port                   string // ip "*" or "::" for a wildcard
	ssl, def, proxy, quic, bad bool
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
	flat := func(d crossplane.Directives) crossplane.Directives { return flatten(payload, d, 0) }
	var out []nginxServer
	for _, top := range flat(payload.Config[0].Parsed) {
		if top.Directive != "http" && top.Directive != "stream" {
			continue
		}
		module := flat(top.Block)
		inherited := certsIn(module, config)
		for _, d := range module {
			if d.Directive != "server" {
				continue
			}
			out = append(out, serverOf(flat(d.Block), top.Directive == "stream", inherited, config))
		}
	}
	return out, nil
}

// flatten is dirs with every include replaced by what it includes, so a
// directive in a snippet counts in the context that includes it.
func flatten(p *crossplane.Payload, dirs crossplane.Directives, depth int) crossplane.Directives {
	var out crossplane.Directives
	for _, d := range dirs {
		if d.Directive != "include" || depth > 16 {
			out = append(out, d)
			continue
		}
		for _, i := range d.Includes {
			if i < len(p.Config) {
				out = append(out, flatten(p, p.Config[i].Parsed, depth+1)...)
			}
		}
	}
	return out
}

func certsIn(dirs crossplane.Directives, config string) []string {
	var out []string
	for _, d := range dirs {
		if d.Directive == "ssl_certificate" && len(d.Args) > 0 {
			p, _ := resolve(d.Args[0], config)
			out = append(out, p)
		}
	}
	return out
}

func serverOf(dirs crossplane.Directives, stream bool, inherited []string, config string) nginxServer {
	s := nginxServer{stream: stream, certs: certsIn(dirs, config)}
	if len(s.certs) == 0 {
		s.certs = inherited
	}
	sslOn := false
	for _, d := range dirs {
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

// endpointsFor lists where the servers serve the certificate at path, once
// each, asking for alg ("RSA", "ECDSA") where a server holds certificates of
// more than one key type.
func endpointsFor(servers []nginxServer, path, alg string) []tlscheck.Endpoint {
	// Which server owns each exact name and each wildcard on each address,
	// the first to name it, and which server is each address's default.
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
	var out []tlscheck.Endpoint
	seen := map[string]bool{}
	for i, s := range servers {
		if !loads(s, path) {
			continue
		}
		want := ""
		if len(s.certs) > 1 {
			want = alg
		}
		for _, l := range s.listens {
			if l.bad || !l.ssl || l.proxy || l.quic {
				continue
			}
			k := l.key()
			ip := l.ip
			switch ip {
			case "*":
				if loopback[l.port] {
					continue
				}
				ip = "127.0.0.1"
			case "::":
				if loopback[l.port] {
					continue
				}
				ip = "::1"
			}
			sni, ok := "", false
			if !s.stream {
				for _, n := range s.names {
					name := checkName(n)
					if name != "" && owner[k+"|"+n] == i {
						sni, ok = name, true
						break
					}
				}
			}
			if !ok && (s.stream || def[k] == i) {
				ok = true
			}
			if !ok {
				continue
			}
			e := tlscheck.Endpoint{IP: ip, Port: l.port, SNI: sni, Alg: want}
			if !seen[e.String()] {
				seen[e.String()] = true
				out = append(out, e)
			}
		}
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
	} else if strings.HasPrefix(n, ".") {
		n = strings.TrimPrefix(n, ".")
	}
	if n == "" || strings.ContainsAny(n, "*~$()[]{}\\^ ") || net.ParseIP(n) != nil || !strings.Contains(n, ".") && n != "localhost" {
		return ""
	}
	return strings.ToLower(n)
}
