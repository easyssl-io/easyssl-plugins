package ops

import (
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/tlscheck"
)

// What httpd itself reports about a master's configuration, and how httpd picks
// a virtual host for a connection. Nothing here parses configuration files: the
// configuration is read through `-t -D DUMP_CONFIG` (mod_info, loaded for that
// one run), which has every <IfModule> and <IfDefine> already evaluated, every
// ${VAR} expanded and every Include followed, with each directive's file and
// line; and the virtual hosts through `-t -D DUMP_VHOSTS`, in the order httpd
// matches names, with the names httpd itself settled on.

// ---- what httpd reports ------------------------------------------------------

type directive struct {
	file string
	line int
	args []string
}

type vhostCfg struct {
	file       string
	line       int
	addrs      []string
	engine     *bool
	engineWord string
	certs      []directive
	keys       []directive
	chains     []directive
	proxy      bool
	entries    map[string]*vhEntry // per address set, from DUMP_VHOSTS
}

type serverCfg struct {
	listens []directive
	engine  *bool
	certs   []directive
	keys    []directive
	chains  []directive
	proxy   bool
	// passDialog is SSLPassPhraseDialog as written, "" for the default
	// (builtin), which asks on a terminal and so cannot run unattended.
	passDialog string
	vhosts     []*vhostCfg
	sets       map[string]*vhSet // "addr:port" -> name-based set, from DUMP_VHOSTS
}

type vhEntry struct {
	name, file string
	line       int
	aliases    []string
	wild       []string
}

type vhSet struct{ entries []*vhEntry } // entries[0] is the default

var (
	inFileRe = regexp.MustCompile(`^# In file: (.+)$`)
	lineRe   = regexp.MustCompile(`^\s*#\s+(\d+):\s*$`)
)

// tokens splits a directive line the way httpd reads its arguments
// (ap_getword_conf): a word starting with a double or a single quote runs to
// the next unescaped quote of the same kind, which is dropped with a
// backslash before it, and any other word to the next blank. mod_info's dump
// prints each argument as the configuration wrote it, so both quotes reach
// here.
func tokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		var cur strings.Builder
		if q := s[i]; q == '"' || q == '\'' {
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == q {
					i++
				}
				cur.WriteByte(s[i])
			}
			i++ // the closing quote
		} else {
			for ; i < len(s) && s[i] != ' ' && s[i] != '\t'; i++ {
				cur.WriteByte(s[i])
			}
		}
		out = append(out, cur.String())
	}
	return out
}

// parseDump reads `-t -D DUMP_CONFIG` output: conditionals already evaluated,
// variables expanded, each directive preceded by its file and line.
func parseDump(out string) *serverCfg {
	s := &serverCfg{sets: map[string]*vhSet{}}
	file, line, depth, vdepth := "", 0, 0, -1
	var cur *vhostCfg
	on := func(a []string) *bool { b := len(a) > 0 && strings.EqualFold(a[0], "on"); return &b }
	for _, raw := range strings.Split(out, "\n") {
		if m := inFileRe.FindStringSubmatch(raw); m != nil {
			file = m[1]
			continue
		}
		if m := lineRe.FindStringSubmatch(raw); m != nil {
			line, _ = strconv.Atoi(m[1])
			continue
		}
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "</") {
			depth--
			if cur != nil && depth == vdepth {
				cur, vdepth = nil, -1
			}
			continue
		}
		if strings.HasPrefix(t, "<") {
			tk := tokens(strings.TrimSuffix(strings.TrimPrefix(t, "<"), ">"))
			if len(tk) > 0 && strings.EqualFold(tk[0], "VirtualHost") && cur == nil {
				cur = &vhostCfg{file: file, line: line, addrs: tk[1:], entries: map[string]*vhEntry{}}
				s.vhosts = append(s.vhosts, cur)
				vdepth = depth
			}
			depth++
			continue
		}
		tk := tokens(t)
		if len(tk) == 0 {
			continue
		}
		d := directive{file, line, tk[1:]}
		inVhost := cur != nil && depth == vdepth+1
		if !inVhost && depth != 0 {
			continue // inside <Directory> and the like, where none of these is allowed
		}
		switch strings.ToLower(tk[0]) {
		case "listen":
			if !inVhost {
				s.listens = append(s.listens, d)
			}
		case "sslengine":
			if inVhost {
				cur.engine = on(d.args)
				if len(d.args) > 0 {
					cur.engineWord = d.args[0]
				}
			} else {
				s.engine = on(d.args)
			}
		case "sslcertificatefile":
			if inVhost {
				cur.certs = append(cur.certs, d)
			} else {
				s.certs = append(s.certs, d)
			}
		case "sslcertificatekeyfile":
			if inVhost {
				cur.keys = append(cur.keys, d)
			} else {
				s.keys = append(s.keys, d)
			}
		case "sslcertificatechainfile":
			if inVhost {
				cur.chains = append(cur.chains, d)
			} else {
				s.chains = append(s.chains, d)
			}
		case "sslpassphrasedialog":
			if !inVhost {
				s.passDialog = strings.Join(d.args, " ")
			}
		case "remoteipproxyprotocol":
			if inVhost {
				cur.proxy = cur.proxy || *on(d.args)
			} else {
				s.proxy = s.proxy || *on(d.args)
			}
		}
	}
	return s
}

var (
	setRe    = regexp.MustCompile(`^(\S+)\s+is a NameVirtualHost$`)
	nameRe2  = regexp.MustCompile(`^\s+port \S+ namevhost (\S+) \((.+):(\d+)\)$`)
	singleRe = regexp.MustCompile(`^(\S+)\s+(\S+) \((.+):(\d+)\)$`)
	aliasRe  = regexp.MustCompile(`^\s+(wild )?alias (\S+)$`)
)

// parseVhosts reads `-t -D DUMP_VHOSTS`: each address set in the order httpd
// matches names, with the names and aliases httpd itself settled on.
func parseVhosts(out string, s *serverCfg) {
	var set *vhSet
	var last *vhEntry
	add := func(addr string, e *vhEntry) {
		set.entries = append(set.entries, e)
		last = e
		for _, v := range s.vhosts {
			if v.file == e.file && v.line == e.line {
				v.entries[addr] = e
			}
		}
	}
	addr := ""
	for _, l := range strings.Split(out, "\n") {
		if m := setRe.FindStringSubmatch(l); m != nil {
			addr, set = m[1], &vhSet{}
			s.sets[addr] = set
			continue
		}
		if m := nameRe2.FindStringSubmatch(l); m != nil && set != nil {
			n, _ := strconv.Atoi(m[3])
			add(addr, &vhEntry{name: m[1], file: m[2], line: n})
			continue
		}
		if m := aliasRe.FindStringSubmatch(l); m != nil && last != nil {
			if m[1] != "" {
				last.wild = append(last.wild, m[2])
			} else {
				last.aliases = append(last.aliases, m[2])
			}
			continue
		}
		if m := singleRe.FindStringSubmatch(l); m != nil && !strings.HasPrefix(l, " ") {
			addr, set = m[1], &vhSet{}
			s.sets[addr] = set
			n, _ := strconv.Atoi(m[4])
			add(addr, &vhEntry{name: m[2], file: m[3], line: n})
		}
	}
}

// ---- how httpd picks a vhost -------------------------------------------------

func hostKey(ip, port string) string {
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return ip + ":" + port
}

// setFor is httpd's first phase: the exact address beats *, an exact port
// beats a wildcard port.
func (s *serverCfg) setFor(ip, port string) (string, *vhSet) {
	for _, k := range []string{hostKey(ip, port), hostKey(ip, "*"), "*:" + port, "*:*"} {
		if set, ok := s.sets[k]; ok {
			return k, set
		}
	}
	return "", nil
}

// route is the second phase: the first vhost whose ServerName or ServerAlias
// matches, otherwise the first vhost of the set.
func route(set *vhSet, sni string) *vhEntry {
	if len(set.entries) == 1 || sni == "" {
		return set.entries[0]
	}
	n := strings.ToLower(sni)
	for _, e := range set.entries {
		if strings.EqualFold(e.name, n) {
			return e
		}
		for _, a := range e.aliases {
			if strings.EqualFold(a, n) {
				return e
			}
		}
		for _, w := range e.wild {
			if ok, _ := path.Match(strings.ToLower(w), n); ok {
				return e
			}
		}
	}
	return set.entries[0]
}

func (s *serverCfg) cfgOf(e *vhEntry) *vhostCfg {
	for _, v := range s.vhosts {
		if v.file == e.file && v.line == e.line {
			return v
		}
	}
	return nil
}

func (s *serverCfg) engineOn(v *vhostCfg) bool {
	if v != nil && v.engine != nil {
		return *v.engine
	}
	return s.engine != nil && *s.engine
}

// hostnameRe is what SNI may carry: a DNS name, never an IP address (RFC 6066,
// section 3). A vhost without ServerName can be named after an address,
// "fe80::5055:55ff:fed4:3479%eth0" on Fedora, Debian and Ubuntu here.
var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// isHostname also rules out dotted IPv4 addresses, which the pattern alone accepts.
func isHostname(n string) bool {
	return hostnameRe.MatchString(n) && net.ParseIP(n) == nil
}

type endpoint struct{ ip, port, sni, alg string }

// String reads "ADDR:PORT sni=NAME", plus "key=ALG" when the vhost serves
// more than one certificate and a client must ask for this one's key type.
func (e endpoint) String() string { return e.check().String() }

func (e endpoint) check() tlscheck.Endpoint {
	return tlscheck.Endpoint{IP: e.ip, Port: e.port, SNI: e.sni, Alg: e.alg}
}

func splitAddr(a string) (string, string) {
	a = strings.Replace(a, "_default_", "*", 1)
	i := strings.LastIndex(a, ":")
	if i < 0 || strings.HasSuffix(a, "]") {
		return strings.Trim(a, "[]"), "*"
	}
	return strings.Trim(a[:i], "[]"), a[i+1:]
}

// localIPs are the addresses a check can connect to for a * vhost.
var localIPs = func() []string {
	out := []string{"127.0.0.1"}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			out = append(out, n.IP.String())
		}
	}
	return append(out, "::1")
}

// listen returns the address and port of a Listen directive; a bare
// "Listen 443" has no address.
func listen(l directive) (string, string) {
	if len(l.args) == 0 {
		return "", ""
	}
	ip, port := splitAddr(l.args[0])
	if port == "*" {
		return "", ip
	}
	return ip, port
}

// listened says whether a connection to cip:port reaches httpd at all.
// Listen [::] also takes IPv4: httpd accepts IPv4-mapped connections on it
// (case V3: 127.0.0.1 reached a vhost opened only by Listen [::]:9473).
func (s *serverCfg) listened(cip, port string) bool {
	for _, l := range s.listens {
		lip, lport := listen(l)
		if lport != port {
			continue
		}
		v4 := net.ParseIP(cip).To4() != nil
		if lip == "" || lip == "::" || lip == cip || (lip == "0.0.0.0" && v4) {
			return true
		}
	}
	return false
}

func (s *serverCfg) listenPorts() []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range s.listens {
		if _, p := listen(l); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// sniCandidates are the names a check may send to reach e: its ServerName and
// aliases when they are host names, and for a wildcard alias "*.d" a made-up
// name under d.
func sniCandidates(e *vhEntry) []string {
	var out []string
	for _, n := range append([]string{e.name}, e.aliases...) {
		if isHostname(n) {
			out = append(out, n)
		}
	}
	for _, w := range e.wild {
		if d, ok := strings.CutPrefix(w, "*."); ok && isHostname(d) {
			out = append(out, "easyssl-check."+d)
		}
	}
	return out
}

// msg is one finding, worded per language when it is rendered, so a warning
// that strings several of them together reads in one language throughout.
type msg func(p l10n.Printer) string

// endpointsOf finds, for one address of v, where a client reaches v: an
// address it can connect to, a port httpd listens on, and an SNI name for
// which httpd picks v. A wildcard port yields one endpoint per Listen port
// that reaches v. When there is none, it says why.
func (s *serverCfg) endpointsOf(v *vhostCfg, addr string) ([]endpoint, msg) {
	at := fmt.Sprintf("%s:%d", v.file, v.line)
	ip, port := splitAddr(addr)
	ports := []string{port}
	if port == "*" {
		ports = s.listenPorts()
	}
	cands := []string{ip}
	if ip == "*" {
		cands = localIPs()
	}
	var eps []endpoint
	var taken []string
	anyListen := false
	for _, p := range ports {
	addrs:
		for _, cip := range cands {
			if !s.listened(cip, p) {
				continue
			}
			anyListen = true
			key, set := s.setFor(cip, p)
			if set == nil {
				continue
			}
			e := v.entries[key]
			if e == nil {
				taken = append(taken, fmt.Sprintf("`%s` → `%s:%d`", hostKey(cip, p), set.entries[0].file, set.entries[0].line))
				continue
			}
			if def := s.cfgOf(set.entries[0]); !s.engineOn(def) {
				defAt := fmt.Sprintf("%s:%d", set.entries[0].file, set.entries[0].line)
				return nil, func(pr l10n.Printer) string {
					return pr.T("apache.problem.plain_default",
						"The virtual host at `{vhost}` is on `{address}`, whose default virtual host (`{default}`) does not use TLS, so that port speaks plain HTTP.",
						"vhost", at, "address", key, "default", defAt)
				}
			}
			for _, n := range sniCandidates(e) {
				if route(set, n) == e {
					eps = append(eps, endpoint{ip: cip, port: p, sni: n})
					break addrs
				}
			}
			if route(set, "") == e {
				eps = append(eps, endpoint{ip: cip, port: p})
				break
			}
			// Unreachable by name: nameCollisions reports it, together with the
			// virtual host that takes the name.
			return nil, nil
		}
	}
	if len(eps) > 0 {
		return eps, nil
	}
	if !anyListen {
		return nil, func(pr l10n.Printer) string {
			return pr.T("apache.problem.not_listened",
				"Nothing listens where the virtual host at `{vhost}` could be reached (`{address}`, no matching `Listen`), so it is never reached.",
				"vhost", at, "address", addr)
		}
	}
	if len(taken) > 0 {
		list := strings.Join(taken, ", ")
		return nil, func(pr l10n.Printer) string {
			return pr.T("apache.problem.more_specific",
				"Every address the virtual host at `{vhost}` could be reached at belongs to a more specific virtual host ({taken}).",
				"vhost", at, "taken", list)
		}
	}
	return nil, func(pr l10n.Printer) string {
		return pr.T("apache.problem.not_listed", "httpd lists the virtual host at `{vhost}` for no address.", "vhost", at)
	}
}

// collision is a configuration where one virtual host, or one certificate,
// hides another: Apache never serves the hidden one, yet still loads its files
// on every reload, so a broken file there takes the server down (a mismatched
// key in a never-selected virtual host made the master exit on a test host).
// It is a warning of every certificate involved, the same text for each, so
// none of them is suggested and the operator fixes it before it bites.
type collision struct {
	say msg
}

// nameCollisions finds, in each address set, every virtual host that never
// gets a name it declares because an earlier one takes it, and pairs it with
// that virtual host. A name that is not a host name (an IP address, an
// address-derived name) is taken by the set's default virtual host, since
// clients reach it without SNI.
func (s *serverCfg) nameCollisions() map[*vhostCfg]*collision {
	out := map[*vhostCfg]*collision{}
	var keys []string
	for k := range s.sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		set := s.sets[k]
		if len(set.entries) < 2 {
			continue
		}
		involved := map[*vhEntry]bool{}
		var items []msg
		taken := func(e *vhEntry, name string, isAlias bool) {
			var w *vhEntry
			notHost := false
			if isHostname(name) {
				w = route(set, name)
			} else if e != set.entries[0] {
				w, notHost = set.entries[0], true
			}
			if w == nil || w == e {
				return
			}
			involved[e], involved[w] = true, true
			at, winner := fmt.Sprintf("%s:%d", e.file, e.line), fmt.Sprintf("%s:%d", w.file, w.line)
			items = append(items, func(p l10n.Printer) string {
				switch {
				case notHost:
					return p.T("apache.collision.not_hostname",
						"`{vhost}` never gets its name `{name}`, which is not a host name, so clients reach it without SNI and get `{winner}`",
						"vhost", at, "name", name, "winner", winner)
				case isAlias:
					return p.T("apache.collision.alias", "`{vhost}` never gets its alias `{name}`, which `{winner}` takes",
						"vhost", at, "name", name, "winner", winner)
				}
				return p.T("apache.collision.name", "`{vhost}` never gets its name `{name}`, which `{winner}` takes",
					"vhost", at, "name", name, "winner", winner)
			})
		}
		for _, e := range set.entries {
			taken(e, e.name, false)
			for _, a := range e.aliases {
				taken(e, a, true)
			}
		}
		if len(involved) == 0 {
			continue
		}
		key := k
		c := &collision{say: func(p l10n.Printer) string {
			var parts []string
			for _, it := range items {
				parts = append(parts, it(p))
			}
			return p.T("apache.warning.name_collision",
				"Name collision on `{address}`: {items}. Apache picks the first virtual host that matches a name, "+
					"so a virtual host is never served for a name another one takes, yet Apache still loads its certificate "+
					"on every reload. Give each virtual host names of its own.",
				"address", key, "items", strings.Join(parts, "; "))
		}}
		for e := range involved {
			if v := s.cfgOf(e); v != nil {
				out[v] = c
			}
		}
	}
	return out
}
