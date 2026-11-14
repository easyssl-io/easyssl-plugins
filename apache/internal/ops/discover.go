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
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-plugins/internal/buildversion"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Describe answers with what this Plugin is and declares, reading nothing from
// the host.
func Describe() DescribeResponse {
	return DescribeResponse{
		ContractVersion: plugincontractVersion,
		Version:         buildversion.Version,
		Description: T("apache.description",
			"Installs Certificates into the Apache HTTP Server (httpd, apache2). It finds the certificates every running "+
				"Apache serves, and installs a new one by writing the files, testing the configuration, reloading only "+
				"when that passes, and checking that the new Certificate is then served. It runs as root on the host: whoever can "+
				"edit a Target's settings can have it run any command and write any file there."),
		Declarations: declarations(),
	}
}

// Discover answers with what this host's Apache serves: every certificate file
// it loads, with the directives that name it. One is suggested only when
// everything about how Apache uses it is sound; any finding is a warning of
// its own instead, so an operator fixes it before a renewal meets it.
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
	m     *master
	where string // the SSLCertificateFile's file:line
	// certDir and keyDir are the directives naming the files, keyDir nil when
	// none pairs with the certificate.
	certDir   directive
	keyDir    *directive
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
// reaches it, and what is wrong with it, and warns about an
// SSLCertificateFile that names no file, of which no Target can be made.
func locationsOf(m *master, s *serverCfg, changed []string) ([]*location, []l10n.Text) {
	var changes []msg
	for _, f := range changed {
		file := f
		changes = append(changes, func(p l10n.Printer) string {
			return p.T("apache.problem.config_changed",
				"`{file}` changed since the instance last loaded its configuration, so a reload would also apply those edits.",
				"file", file)
		})
	}
	colls := s.nameCollisions()
	var locs []*location
	var warnings []l10n.Text
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
				coll = &collision{say: func(p l10n.Printer) string {
					return p.T("apache.warning.same_key_type",
						"{count} {alg} certificates in one place ({places}): Apache serves only the last of each key type, "+
							"yet loads every one on every reload. Keep one certificate per key type.",
						"count", n, "alg", alg, "places", places)
				}}
			}
		}
		if len(chains) > 0 {
			at := fmt.Sprintf("%s:%d", chains[0].file, chains[0].line)
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.chain_file",
					"It is used with `SSLCertificateChainFile` (`{at}`), which is deprecated since httpd 2.4.8: `SSLCertificateFile` "+
						"loads the intermediate certificates itself, and a Deployment writes the full chain there, so the intermediates "+
						"would be sent twice. Remove the `SSLCertificateChainFile` directive and put the chain in the certificate file.",
					"at", at)
			})
		}
		common = append(common, changes...)
		for i, c := range certs {
			if uriRe.MatchString(c.args[0]) {
				warnings = append(warnings, T("apache.warning.not_a_file",
					"`{value}` (`{at}`) names a certificate held in a token rather than a file, so a Deployment has no file to write, and nothing there is reported",
					"value", c.args[0], "at", fmt.Sprintf("%s:%d", c.file, c.line)))
				continue
			}
			var uris []msg
			if i < len(keys) && uriRe.MatchString(keys[i].args[0]) {
				value, at := keys[i].args[0], fmt.Sprintf("%s:%d", keys[i].file, keys[i].line)
				uris = append(uris, func(p l10n.Printer) string {
					return p.T("apache.problem.key_not_a_file",
						"Its key `{value}` (`{at}`) is held in a token rather than a file, so a Deployment has no file to write it to.",
						"value", value, "at", at)
				})
			}
			l := &location{m: m, where: fmt.Sprintf("%s:%d", c.file, c.line), certDir: c, vhost: v,
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
			switch {
			case i < len(keys) && uriRe.MatchString(keys[i].args[0]):
				l.keyDir, l.keyPath = &keys[i], keys[i].args[0]
			case i < len(keys):
				l.keyDir, l.keyPath = &keys[i], resolveIn(s.root(m), keys[i].args[0])
			default:
				at := l.where
				if b, err := os.ReadFile(l.certPath); err == nil && pemfile.HasPrivateKey(b) {
					l.problems = append(l.problems, func(p l10n.Printer) string {
						return p.T("apache.problem.key_in_cert",
							"The private key is inside the certificate file (no `SSLCertificateKeyFile` for `{at}`), and a Deployment writes them as two files.",
							"at", at)
					})
				} else {
					l.problems = append(l.problems, func(p l10n.Printer) string {
						return p.T("apache.problem.no_key", "No `SSLCertificateKeyFile` pairs with the certificate at `{at}`.", "at", at)
					})
				}
			}
			l.coll = coll
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
					"`SSLEngine optional` in the virtual host at `{vhost}` is no longer supported by httpd 2.4, which treats the port as plain HTTP (AH10510), so it never serves this certificate.",
					"vhost", at)
			})
		case !s.engineOn(v):
			common = append(common, func(p l10n.Printer) string {
				return p.T("apache.problem.engine_off", "`SSLEngine` is off in the virtual host at `{vhost}`, so it never serves this certificate.", "vhost", at)
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
					"The virtual host at `{vhost}` expects the PROXY protocol (`RemoteIPProxyProtocol On`), so a local connection cannot check what it serves.",
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
						"The main server expects the PROXY protocol (`RemoteIPProxyProtocol On`), so a local connection cannot check what it serves.")
				})
			}
			use(s.certs, s.keys, s.chains, nil, eps, common, nil)
		}
	}
	if len(s.certs) > 0 && !serverLevelUsed {
		at := fmt.Sprintf("%s:%d", s.certs[0].file, s.certs[0].line)
		use(s.certs, s.keys, s.chains, nil, nil, []msg{func(p l10n.Printer) string {
			return p.T("apache.problem.unused_server_level",
				"It is configured at server level (`{at}`), but every TLS virtual host has its own certificate and the main server serves no TLS, so nothing serves it.",
				"at", at)
		}}, nil)
	}
	return locs, warnings
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

// survey is a host's analysis: every certificate file and its problems, and
// the warnings that belong to an instance, or to a value naming no file,
// rather than to a certificate file.
type survey struct {
	files    []*certFile
	problems map[string][]msg // per certificate path, collisions included
	warnings []l10n.Text
	infos    map[string]certInfo
	readErr  map[string]error
	cfgs     map[*master]*serverCfg
	// changed is each master's configuration files edited since it loaded
	// them.
	changed map[*master][]string
}

func surveyOf(masters []*master, read configReader) *survey {
	sv := &survey{problems: map[string][]msg{}, infos: map[string]certInfo{}, readErr: map[string]error{},
		cfgs: map[*master]*serverCfg{}, changed: map[*master][]string{}}
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
		sv.cfgs[m], sv.changed[m] = s, changed
		locs, warnings := locationsOf(m, s, changed)
		sv.warnings = append(sv.warnings, warnings...)
		for _, l := range locs {
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
	for _, f := range sv.files {
		sv.problems[f.path] = sv.fileProblems(f)
	}
	return sv
}

// fileProblems is everything that keeps one certificate file from being
// suggested.
func (sv *survey) fileProblems(f *certFile) []msg {
	var out []msg
	keys, pids := map[string]bool{}, map[int]bool{}
	for _, l := range f.locs {
		if l.coll != nil {
			out = append(out, l.coll.say)
		}
		out = append(out, l.problems...)
		pids[l.m.PID] = true
		if l.keyPath != "" {
			keys[l.keyPath] = true
		}
	}
	ci, err := readCert(f.path)
	sv.infos[f.path], sv.readErr[f.path] = ci, err
	if err != nil {
		why := err.Error()
		out = append(out, func(p l10n.Printer) string {
			return p.T("apache.problem.unreadable_certificate", "It holds no certificate this Plugin can read: {error}.", "error", why)
		})
	} else if ci.sanErr != nil {
		why := ci.sanErr.Error()
		out = append(out, func(p l10n.Printer) string {
			return p.T("apache.problem.names_unreadable", "Its names could not be read: {error}.", "error", why)
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
				"{count} Apache instances load it ({instances}), and a renewal is complete only once every one of them has reloaded. Give each instance its own copy.",
				"count", n, "instances", list)
		})
	}
	files := map[string]bool{} // the keys that are files
	for k := range keys {
		if !uriRe.MatchString(k) {
			files[k] = true
		}
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
					"It is paired with several key files holding the same key ({keys}); point every use at one file, "+
						"since a renewal writes only one and the next reload then fails on a key that no longer matches.",
					"keys", list)
			})
		} else {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_conflict.different",
					"It is paired with different keys ({keys}), so at least one place pairs it with a key that does not match, "+
						"and the next reload fails there.",
					"keys", list)
			})
		}
	}
	var sorted []string
	for k := range files {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	out = append(out, pathProblems(f.path, false)...)
	for _, k := range sorted {
		out = append(out, pathProblems(k, true)...)
	}
	for _, k := range sorted {
		if b, err := os.ReadFile(k); err == nil && pemfile.EncryptedKey(b) {
			key := k
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.encrypted_key", "Its key `{key}` is protected by a passphrase, and a Deployment cannot keep that protection.", "key", key)
			})
		}
	}
	for _, l := range f.locs {
		pid, uid := l.m.PID, l.m.Cred.UID
		if !readableBy(l.m.Cred, l.certPath) {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.unreadable",
					"`pid {pid}` runs as uid {uid} and cannot read the certificate file, so its next reload or restart fails.",
					"pid", pid, "uid", uid)
			})
		}
		if key := l.keyPath; files[key] && !readableBy(l.m.Cred, key) {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.key_unreadable",
					"`pid {pid}` runs as uid {uid} and cannot read its key `{key}`, so its next reload or restart fails.",
					"pid", pid, "uid", uid, "key", key)
			})
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

// warningsOf is what keeps f from being suggested, each finding a warning of
// its own: none means it is suggested.
func (sv *survey) warningsOf(f *certFile) []l10n.Text {
	out := []l10n.Text{}
	for _, m := range sv.problems[f.path] {
		out = append(out, perLanguage(m))
	}
	return out
}

// referencesOf is every directive the locations name a file with, once each:
// the SSLCertificateFile and, when it names a file, the SSLCertificateKeyFile
// mod_ssl pairs with it, each with its argument as written in the file.
// Sorted by file and line, so two runs compare equal. relocate finds the
// references a move changes with this too, so what it changes is what
// discovery reported.
func referencesOf(locs []*location) []plugincontract.Reference {
	seen := map[plugincontract.Reference]bool{}
	out := []plugincontract.Reference{}
	add := func(r plugincontract.Reference) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, l := range locs {
		add(plugincontract.Reference{Setting: SettingCertificate, File: l.certDir.file, Line: l.certDir.line,
			Value: asWritten(l.certDir, SettingCertificate)})
		if k := l.keyDir; k != nil && !uriRe.MatchString(k.args[0]) {
			add(plugincontract.Reference{Setting: SettingKey, File: k.file, Line: k.line, Value: asWritten(*k, SettingKey)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Setting != b.Setting {
			return a.Setting < b.Setting
		}
		return a.Value < b.Value
	})
	return out
}

// analyze turns a survey into what discover answers: a discovered Target per
// certificate file, with its references and its own warnings, and a warning
// per instance that could not be read and per value that names no file.
func analyze(masters []*master, read configReader) ([]DiscoveredTarget, []l10n.Text) {
	sv := surveyOf(masters, read)
	targets := []DiscoveredTarget{}
	warnings := append([]l10n.Text{}, sv.warnings...)
	for _, f := range sv.files {
		first := f.locs[0]
		t := DiscoveredTarget{
			Settings: map[string]string{
				SettingCertificate: f.path,
				SettingKey:         first.keyPath,
				SettingTest:        first.m.testCommand(),
				SettingReload:      first.m.reloadCommand(),
			},
			ExtraData:  []ExtraDatum{},
			References: referencesOf(f.locs),
			Warnings:   sv.warningsOf(f),
		}
		if len(t.References) > plugincontract.MaxReferences {
			// The answer would be refused whole; a move of this certificate is
			// refused instead, since its confirmed references would not be
			// all of them.
			t.References = t.References[:plugincontract.MaxReferences]
		}
		if sv.readErr[f.path] == nil {
			ci := sv.infos[f.path]
			// TODO: report the SSLCertificateChainFile's certificates as the
			// chain when the certificate file holds only the leaf, since that
			// deprecated layout sends them from there.
			t.Certificate = &DiscoveredCertificate{Domains: ci.sans, KeyType: ci.keyType, SHA256: ci.sha256,
				CertificatePem: ci.leafPEM, ChainPem: ci.chainPEM}
			if ci.sans == nil {
				t.Certificate.Domains = []string{}
			}
		}
		targets = append(targets, t)
	}
	targets, warnings = capped(targets, warnings)
	budgetPEM(targets)
	return targets, warnings
}

// capped keeps an answer within the contract's bound on discovered Targets,
// which the Agent would otherwise refuse whole: the suggested ones first, then
// the warned, and a warning counting what was left out.
// budgetPEM keeps the PEM the answer's certificates carry within
// pemfile.MaxReportedPEM, so an Agent does not refuse the answer for its size.
func budgetPEM(targets []DiscoveredTarget) {
	var pairs []pemfile.PEMPair
	for i := range targets {
		if c := targets[i].Certificate; c != nil {
			pairs = append(pairs, pemfile.PEMPair{Leaf: &c.CertificatePem, Chain: &c.ChainPem})
		}
	}
	pemfile.Budget(pairs, pemfile.MaxReportedPEM)
}

func capped(targets []DiscoveredTarget, warnings []l10n.Text) ([]DiscoveredTarget, []l10n.Text) {
	if len(targets) <= plugincontract.MaxDiscoveredTargets {
		return targets, warnings
	}
	sort.SliceStable(targets, func(i, j int) bool { return len(targets[i].Warnings) == 0 && len(targets[j].Warnings) > 0 })
	left := len(targets) - plugincontract.MaxDiscoveredTargets
	targets = targets[:plugincontract.MaxDiscoveredTargets]
	sort.SliceStable(targets, func(i, j int) bool {
		return targets[i].Settings[SettingCertificate] < targets[j].Settings[SettingCertificate]
	})
	return targets, append(warnings, T("apache.warning.too_many",
		"{count} more certificates were found and are not reported, because one answer reports at most {max}.",
		"count", left, "max", plugincontract.MaxDiscoveredTargets))
}
