package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Describe answers with what this Plugin is and declares, reading nothing from
// the host.
func Describe() DescribeResponse {
	return DescribeResponse{
		ContractVersion: plugincontractVersion,
		Name:            Name,
		Version:         Version(),
		Description: T("apache.description",
			"Installs Certificates into the Apache HTTP Server (httpd, apache2). It finds the certificates every running "+
				"Apache serves, and installs a new one by writing the files, testing the configuration, reloading only "+
				"when that passes, and checking that the new Certificate is then served."),
		Declarations: declarations(),
	}
}

// Discover answers with what this host's Apache serves. A certificate is
// suggested only when everything about how Apache uses it is sound; any finding
// is a warning instead, so an operator fixes it before a renewal meets it.
// discover never fails for what it finds.
func Discover() DiscoverResponse {
	resp := DiscoverResponse{
		ContractVersion:   plugincontractVersion,
		DiscoveredTargets: []DiscoveredTarget{},
		Warnings:          []l10n.Text{},
	}
	masters, err := scan()
	if err != nil {
		resp.Warnings = append(resp.Warnings, textOf(err))
		return resp
	}
	resp.DiscoveredTargets, resp.Warnings = analyze(masters, readConfig)
	return resp
}

// configReader reads what httpd reports about a master's configuration and
// which of its files changed since it was loaded. A variable seam so the
// tests run every case against captured httpd output.
type configReader func(m *master) (*serverCfg, []string, error)

func readConfig(m *master) (*serverCfg, []string, error) {
	ctx := context.Background()
	args := []string{"-t", "-D", "DUMP_CONFIG"}
	if mods, _ := m.run(ctx, "-t", "-D", "DUMP_MODULES"); !strings.Contains(mods, "info_module") {
		mi := modInfoPath(m)
		if mi == "" {
			return nil, nil, worded{T("apache.warning.no_mod_info",
				"`pid {pid}` (`{exe}`): `mod_info.so` was not found, so its configuration cannot be read the way Apache reads it, and nothing from it is reported",
				"pid", m.PID, "exe", m.Exe)}
		}
		// Loaded for this one test run only: the host's configuration is not
		// changed, and the dump has every conditional evaluated and every
		// directive's file and line.
		args = append(args, "-C", "LoadModule info_module "+mi)
	}
	out, err := m.run(ctx, args...)
	if err != nil {
		return nil, nil, worded{T("apache.warning.dump_failed",
			"`pid {pid}` (`{exe}`): reading its configuration failed: {error}",
			"pid", m.PID, "exe", m.Exe, "error", firstError(out, err))}
	}
	s := parseDump(out)
	vout, _ := m.run(ctx, "-t", "-D", "DUMP_VHOSTS")
	parseVhosts(vout, s)
	return s, changedSince(m), nil
}

func modInfoPath(m *master) string {
	for _, p := range []string{
		filepath.Join(m.ServerRoot, "modules/mod_info.so"),
		"/usr/lib/apache2/modules/mod_info.so",
		"/usr/lib/apache2/mod_info.so",
		"/usr/lib64/httpd/modules/mod_info.so",
		"/usr/lib/httpd/modules/mod_info.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// clockSlack absorbs wall-clock steps: on a Lima VM a PidFile came out 50 ms
// older than the configuration written before httpd started.
const clockSlack = 2 * time.Second

var includeRe = regexp.MustCompile(`^\s+\((?:\*|\d+)\) (.+)$`)

// changedSince lists the configuration files modified after the master last
// loaded its configuration. That moment is the PidFile's mtime: httpd rewrites
// it at startup and on every restart, on the same clock as the files. The
// process start time is not used: it derives from time since boot, which drifts
// from the wall clock, and a graceful reload loads the configuration without
// restarting the master anyway.
func changedSince(m *master) []string {
	pf, err := os.Stat(m.PidFile)
	if err != nil {
		return nil
	}
	out, _ := m.run(context.Background(), "-t", "-D", "DUMP_INCLUDES")
	var changed []string
	for _, l := range strings.Split(out, "\n") {
		if mm := includeRe.FindStringSubmatch(l); mm != nil {
			if fi, err := os.Stat(mm[1]); err == nil && fi.ModTime().After(pf.ModTime().Add(clockSlack)) {
				changed = append(changed, mm[1])
			}
		}
	}
	return changed
}

// uriRe matches a URI where a file name would be: since httpd 2.4.42,
// SSLCertificateFile and SSLCertificateKeyFile also take a PKCS #11 URI
// ("pkcs11:token=...") naming an object in a token. A path never has a scheme
// before its first slash.
var uriRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[^/]`)

// location is one place a master loads a certificate file.
type location struct {
	m         *master
	where     string // the SSLCertificateFile's file:line
	vhost     *vhostCfg
	certPath  string
	keyPath   string // "" when the key is inside the certificate file
	alg       string
	endpoints []endpoint
	problems  []msg
	coll      *collision
	// siblings are the other certificate files of the same group (virtual
	// host, or server level), for deploy's key-type guard.
	siblings []string
}

func resolveIn(root, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// locationsOf lists every place m loads a certificate file, where a client
// reaches it, and what is wrong with it.
func locationsOf(m *master, s *serverCfg, changed []string) []*location {
	var changes []msg
	for _, f := range changed {
		file := f
		changes = append(changes, func(p l10n.Printer) string {
			return p.T("apache.problem.config_changed",
				"`{file}` changed since the instance last loaded its configuration, so a reload would also apply those edits",
				"file", file)
		})
	}
	colls := s.nameCollisions()
	var locs []*location
	// use adds one location per certificate of a group (a virtual host's own,
	// or the server-level ones where they are used), each paired with its key
	// by position, as mod_ssl pairs them.
	use := func(certs, keys, chains []directive, v *vhostCfg, eps []endpoint, common []msg, coll *collision) {
		infos := make([]certInfo, len(certs))
		byAlg := map[string][]directive{}
		for i, c := range certs {
			infos[i], _ = readCert(resolveIn(s.root(m), c.args[0]))
			byAlg[infos[i].alg()] = append(byAlg[infos[i].alg()], c)
		}
		for a, ds := range byAlg {
			if len(ds) > 1 && coll == nil {
				var at []string
				for _, d := range ds {
					at = append(at, fmt.Sprintf("`%s:%d`", d.file, d.line))
				}
				alg, n, places := a, len(ds), strings.Join(at, ", ")
				// OpenSSL keeps one certificate per key type in a context and
				// replaces it when another of that type is set (the manual of
				// SSL_CTX_use_certificate), and mod_ssl loads the files in
				// order (ssl_init_server_certs), so only the last is served.
				coll = &collision{say: func(p l10n.Printer, certs string) string {
					return p.T("apache.warning.same_key_type",
						"{count} {alg} certificates in one place ({places}): Apache serves only the last of each key type, "+
							"yet loads every one on every reload. Keep one certificate per key type. Not suggested: {certificates}.",
						"count", n, "alg", alg, "places", places, "certificates", certs)
				}}
			}
		}
		if len(chains) > 0 {
			at := fmt.Sprintf("%s:%d", chains[0].file, chains[0].line)
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.chain_file",
					"it is used with `SSLCertificateChainFile` (`{at}`), which is deprecated since httpd 2.4.8: `SSLCertificateFile` "+
						"loads the intermediate certificates itself, and a Deployment writes the full chain there, so the intermediates "+
						"would be sent twice. Remove the `SSLCertificateChainFile` directive and put the chain in the certificate file",
					"at", at)
			})
		}
		common = append(common, changes...)
		for i, c := range certs {
			named := []directive{c}
			if i < len(keys) {
				named = append(named, keys[i])
			}
			var uris []msg
			for _, d := range named {
				if uriRe.MatchString(d.args[0]) {
					value, at := d.args[0], fmt.Sprintf("%s:%d", d.file, d.line)
					uris = append(uris, func(p l10n.Printer) string {
						return p.T("apache.problem.not_a_file",
							"`{value}` (`{at}`) names a key or certificate held in a token rather than a file, so a Deployment has no file to write",
							"value", value, "at", at)
					})
				}
			}
			l := &location{m: m, where: fmt.Sprintf("%s:%d", c.file, c.line), vhost: v,
				certPath: resolveIn(s.root(m), c.args[0]), alg: infos[i].alg()}
			for j, o := range certs {
				if j != i {
					l.siblings = append(l.siblings, resolveIn(s.root(m), o.args[0]))
				}
			}
			for _, e := range eps {
				if len(certs) > 1 { // which one a client gets depends on the key type it offers
					e.alg = l.alg
				}
				l.endpoints = append(l.endpoints, e)
			}
			l.problems = append(l.problems, common...)
			l.problems = append(l.problems, uris...)
			if i < len(keys) {
				l.keyPath = resolveIn(s.root(m), keys[i].args[0])
			} else {
				at := l.where
				if b, err := os.ReadFile(l.certPath); err == nil && pemfile.HasPrivateKey(b) {
					l.problems = append(l.problems, func(p l10n.Printer) string {
						return p.T("apache.problem.key_in_cert",
							"the private key is inside the certificate file (no `SSLCertificateKeyFile` for `{at}`), and a Deployment writes them as two files",
							"at", at)
					})
				} else {
					l.problems = append(l.problems, func(p l10n.Printer) string {
						return p.T("apache.problem.no_key", "no `SSLCertificateKeyFile` pairs with the certificate at `{at}`", "at", at)
					})
				}
			}
			if coll != nil {
				l.coll = coll
				coll.add(l.certPath)
			}
			locs = append(locs, l)
		}
	}

	serverLevelUsed := false
	for _, v := range s.vhosts {
		certs, keys, chains := v.certs, v.keys, v.chains
		if len(certs) == 0 && s.engineOn(v) {
			certs, keys, chains = s.certs, s.keys, s.chains
			serverLevelUsed = serverLevelUsed || len(certs) > 0
		}
		if len(certs) == 0 {
			continue
		}
		at := fmt.Sprintf("%s:%d", v.file, v.line)
		var eps []endpoint
		var common []msg
		switch {
		case !s.engineOn(v) && strings.EqualFold(v.engineWord, "optional"):
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.engine_optional",
					"`SSLEngine optional` in the virtual host at `{vhost}` is no longer supported by httpd 2.4, which treats the port as plain HTTP (AH10510), so it never serves this certificate",
					"vhost", at)
			})
		case !s.engineOn(v):
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.engine_off", "`SSLEngine` is off in the virtual host at `{vhost}`, so it never serves this certificate", "vhost", at)
			})
		case colls[v] == nil:
			for _, a := range v.addrs {
				e, why := s.endpointsOf(v, a)
				if why != nil {
					common = append(common, why)
				}
				eps = append(eps, e...)
			}
		}
		if s.proxy || v.proxy {
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.proxy_protocol",
					"the virtual host at `{vhost}` expects the PROXY protocol (`RemoteIPProxyProtocol On`), so a local connection cannot check what it serves",
					"vhost", at)
			})
		}
		use(certs, keys, chains, v, eps, common, colls[v])
	}

	// The main server answers on every address and port no virtual host covers,
	// with the server-level certificates when SSLEngine is on there.
	if len(s.certs) > 0 && s.engineOn(nil) {
		var eps []endpoint
		for _, port := range s.listenPorts() {
			for _, cip := range localIPs() {
				if _, set := s.setFor(cip, port); set == nil && s.listened(cip, port) {
					eps = append(eps, endpoint{ip: cip, port: port})
					break
				}
			}
		}
		if len(eps) > 0 {
			serverLevelUsed = true
			var common []msg
			if s.proxy {
				common = append(common, func(p l10n.Printer) string {
					return p.T("apache.problem.proxy_protocol_server",
						"the main server expects the PROXY protocol (`RemoteIPProxyProtocol On`), so a local connection cannot check what it serves")
				})
			}
			use(s.certs, s.keys, s.chains, nil, eps, common, nil)
		}
	}
	if len(s.certs) > 0 && !serverLevelUsed {
		at := fmt.Sprintf("%s:%d", s.certs[0].file, s.certs[0].line)
		use(s.certs, s.keys, s.chains, nil, nil, []msg{func(p l10n.Printer) string {
			return p.T("apache.problem.unused_server_level",
				"it is configured at server level (`{at}`), but every TLS virtual host has its own certificate and the main server serves no TLS, so nothing serves it",
				"at", at)
		}}, nil)
	}
	return locs
}

// root is the ServerRoot relative paths resolve against: the one the
// configuration test reported, which a ServerRoot directive can set apart from
// -d.
func (s *serverCfg) root(m *master) string { return m.ServerRoot }

// certFile is one certificate file with every place it is loaded from.
type certFile struct {
	path string
	locs []*location
}

// survey is a host's analysis: every certificate file and its problems, every
// collision, and the warnings that belong to an instance rather than to a
// file.
type survey struct {
	files    []*certFile
	problems map[string][]msg // per certificate path
	colls    []*collision
	warnings []l10n.Text
	infos    map[string]certInfo
	readErr  map[string]error
	cfgs     map[*master]*serverCfg
}

func surveyOf(masters []*master, read configReader) *survey {
	sv := &survey{problems: map[string][]msg{}, infos: map[string]certInfo{}, readErr: map[string]error{}, cfgs: map[*master]*serverCfg{}}
	byPath := map[string]*certFile{}
	for _, m := range masters {
		if m.GateErr != nil {
			sv.warnings = append(sv.warnings, T("apache.warning.configuration_rejected",
				"`pid {pid}` (`{exe}`): Apache rejects its configuration, so nothing from it is reported: {reason}",
				"pid", m.PID, "exe", m.Exe, "reason", m.GateErr.Error()))
			continue
		}
		if m.PidFilePID != m.PID {
			sv.warnings = append(sv.warnings, T("apache.warning.derivation_mismatch",
				"`pid {pid}` (`{exe}`): the PidFile its configuration names (`{pidfile}`) does not hold its pid, so how it was started could not be confirmed, and nothing from it is reported",
				"pid", m.PID, "exe", m.Exe, "pidfile", m.PidFile))
			continue
		}
		s, changed, err := read(m)
		if err != nil {
			sv.warnings = append(sv.warnings, textOf(err))
			continue
		}
		sv.cfgs[m] = s
		for _, l := range locationsOf(m, s, changed) {
			f := byPath[l.certPath]
			if f == nil {
				f = &certFile{path: l.certPath}
				byPath[l.certPath] = f
				sv.files = append(sv.files, f)
			}
			f.locs = append(f.locs, l)
		}
	}
	sort.Slice(sv.files, func(i, j int) bool { return sv.files[i].path < sv.files[j].path })
	seen := map[*collision]bool{}
	for _, f := range sv.files {
		sv.problems[f.path] = sv.fileProblems(f)
		for _, l := range f.locs {
			if l.coll != nil && !seen[l.coll] {
				seen[l.coll] = true
				sv.colls = append(sv.colls, l.coll)
			}
		}
	}
	return sv
}

// fileProblems is everything that keeps one certificate file from being
// suggested, beyond collisions.
func (sv *survey) fileProblems(f *certFile) []msg {
	var out []msg
	keys, pids := map[string]bool{}, map[int]bool{}
	for _, l := range f.locs {
		out = append(out, l.problems...)
		pids[l.m.PID] = true
		if l.keyPath != "" {
			keys[l.keyPath] = true
		}
	}
	ci, err := readCert(f.path)
	sv.infos[f.path], sv.readErr[f.path] = ci, err
	if err != nil {
		path, why := f.path, err.Error()
		out = append(out, func(p l10n.Printer) string {
			return p.T("apache.problem.unreadable_certificate", "`{path}` holds no certificate this Plugin can read: {error}", "path", path, "error", why)
		})
	}
	if len(pids) > 1 {
		var ps []string
		for pid := range pids {
			ps = append(ps, fmt.Sprintf("`pid %d`", pid))
		}
		sort.Strings(ps)
		list, n := strings.Join(ps, ", "), len(pids)
		out = append(out, func(p l10n.Printer) string {
			return p.T("apache.problem.shared",
				"{count} Apache instances load it ({instances}), and a renewal is complete only once every one of them has reloaded. Give each instance its own copy",
				"count", n, "instances", list)
		})
	}
	if len(keys) > 1 {
		var ks []string
		for k := range keys {
			ks = append(ks, "`"+k+"`")
		}
		sort.Strings(ks)
		list := strings.Join(ks, ", ")
		var files []string
		for k := range keys {
			files = append(files, k)
		}
		// Two messages rather than one with advice appended: which applies
		// changes what the reader is told.
		if hostfile.SameContent(files) {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_conflict.same_bytes",
					"it is paired with several key files holding the same key ({keys}); point every use at one file, "+
						"since a renewal writes only one and the next reload then fails on a key that no longer matches",
					"keys", list)
			})
		} else {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_conflict.different",
					"it is paired with different keys ({keys}), so at least one place pairs it with a key that does not match, "+
						"and the next reload fails there",
					"keys", list)
			})
		}
	}
	paths := []string{f.path}
	for k := range keys {
		paths = append(paths, k)
	}
	sort.Strings(paths[1:])
	for _, path := range paths {
		out = append(out, pathProblems(path)...)
	}
	for k := range keys {
		if b, err := os.ReadFile(k); err == nil && pemfile.EncryptedKey(b) {
			key := k
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.encrypted_key", "its key `{key}` is protected by a passphrase, and a Deployment cannot keep that protection", "key", key)
			})
		}
	}
	for _, l := range f.locs {
		for _, path := range []string{l.certPath, l.keyPath} {
			if path != "" && !readableBy(l.m.Cred, path) {
				pid, uid, pth := l.m.PID, l.m.Cred.UID, path
				out = append(out, func(p l10n.Printer) string {
					return p.T("apache.problem.unreadable",
						"`pid {pid}` runs as uid {uid} and cannot read `{path}`, so its next reload or restart fails",
						"pid", pid, "uid", uid, "path", pth)
				})
			}
		}
	}
	return dedupe(out)
}

// dedupe drops findings that render the same, which several locations of one
// file produce.
func dedupe(in []msg) []msg {
	seen := map[string]bool{}
	var out []msg
	for _, m := range in {
		k := m(catalog.In(l10n.English))
		if !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	return out
}

// readableBy asks the kernel, as the master, whether it can read a file.
func readableBy(c cred, path string) bool {
	if c.IsRoot() {
		return true
	}
	_, err := runCmd(c.Sys(), []string{"PATH=/usr/bin:/bin"}, "/bin/sh", "-c", `test -r "$1"`, "sh", path)
	return err == nil
}

// suggestable reports whether a file has nothing against it at all.
func (sv *survey) suggestable(f *certFile) bool {
	if len(sv.problems[f.path]) > 0 {
		return false
	}
	for _, l := range f.locs {
		if l.coll != nil {
			return false
		}
	}
	return true
}

// warningFor is the warning that keeps f from being suggested, nil when it has
// no problem of its own (it may still be part of a collision, whose own
// warning names it).
func (sv *survey) warningFor(f *certFile) *l10n.Text {
	probs := sv.problems[f.path]
	if len(probs) == 0 {
		return nil
	}
	path := f.path
	inColl := false
	for _, l := range f.locs {
		inColl = inColl || l.coll != nil
	}
	w := perLanguage(func(p l10n.Printer) string {
		var parts []string
		for _, m := range probs {
			parts = append(parts, m(p))
		}
		if inColl {
			parts = append(parts, p.T("apache.problem.in_collision", "it is also part of a collision reported separately"))
		}
		return p.T("apache.warning.not_suggested", "`{path}` is not suggested: {problems}.", "path", path, "problems", strings.Join(parts, "; "))
	})
	return &w
}

// analyze turns a survey into what discover answers: a discovered Target per
// suggestable certificate file, and a warning per collision, per file that is
// not suggested, and per instance that could not be read.
func analyze(masters []*master, read configReader) ([]DiscoveredTarget, []l10n.Text) {
	sv := surveyOf(masters, read)
	targets := []DiscoveredTarget{}
	warnings := append([]l10n.Text{}, sv.warnings...)
	for _, c := range sv.colls {
		warnings = append(warnings, c.text())
	}
	for _, f := range sv.files {
		if w := sv.warningFor(f); w != nil {
			warnings = append(warnings, *w)
			continue
		}
		if !sv.suggestable(f) {
			continue // a collision's own warning names it
		}
		first := f.locs[0]
		ci := sv.infos[f.path]
		t := DiscoveredTarget{
			Settings: map[string]string{
				SettingCertificate: f.path,
				SettingKey:         first.keyPath,
				SettingTest:        first.m.testCommand(),
				SettingReload:      first.m.reloadCommand(),
			},
			Certificate: &DiscoveredCertificate{Domains: ci.sans, KeyType: ci.keyType, SHA256: ci.sha256},
		}
		if ci.sans == nil {
			t.Certificate.Domains = []string{}
		}
		if ci.sanErr != nil {
			// Apache serves the file and a Deployment replacing it works; only
			// what this Plugin reads from it is missing, so it is suggested and
			// the missing names are explained.
			path, why := f.path, ci.sanErr.Error()
			warnings = append(warnings, T("apache.warning.names_unreadable",
				"`{path}`: its names could not be read, so none are reported: {error}", "path", path, "error", why))
		}
		var lines []string
		for _, l := range f.locs {
			lines = append(lines, fmt.Sprintf("`%s` (pid %d)", l.where, l.m.PID))
		}
		t.ExtraData = []ExtraDatum{{Label: T("apache.extra.locations", "Locations"), Value: strings.Join(lines, "\n")}}
		targets = append(targets, t)
	}
	return targets, warnings
}
