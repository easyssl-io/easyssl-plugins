package ops

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
	"github.com/easyssl-io/easyssl-contract/wire"
	"github.com/easyssl-io/easyssl-plugins/internal/buildversion"
	"github.com/easyssl-io/easyssl-plugins/internal/hostfile"
	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Discovery, in two halves. scan.go finds the running nginx masters and asks
// each for its reload and test commands; this file parses what each one loads
// and turns it into discovered Targets and warnings, so the tests run every
// configuration case against real files without a running nginx.

// Describe answers with what this Plugin is and declares, reading nothing
// from the host.
func Describe() DescribeResponse {
	return DescribeResponse{
		ContractVersion: plugincontractVersion,
		Version:         buildversion.Version,
		Description: T("nginx.description",
			"Installs Certificates into nginx. It finds the certificates every running nginx serves, "+
				"and installs a new one by writing the files, testing the configuration with `nginx -t`, "+
				"reloading only when that passes, and checking that nginx then serves it. It runs as root on the host: "+
				"whoever can edit a Target's settings can have it run any command and write any file there."),
		Declarations: declarations(),
	}
}

// Discover answers with what this host's nginx serves. A host with no nginx,
// or one this Plugin cannot inspect, answers with no discovered Targets:
// discover never fails for what it finds.
func Discover() DiscoverResponse {
	resp := DiscoverResponse{
		ContractVersion:   plugincontractVersion,
		DiscoveredTargets: []DiscoveredTarget{},
		Warnings:          []l10n.Text{},
	}
	found, err := scan()
	if err != nil {
		resp.Warnings = append(resp.Warnings, textOf(err))
		return resp
	}
	resp.DiscoveredTargets, resp.Warnings = analyze(found)
	return resp
}

// instance is one running nginx master and how to test and reload it.
type instance struct {
	PID        int
	Exe        string
	ConfigPath string
	Reload     string
	// Test is this binary's -t against this configuration, so a Deployment
	// tests the instance the files belong to rather than whatever `nginx`
	// resolves to on PATH.
	Test string

	// Certs is every ssl_certificate this instance loads, with the file and
	// line it came from. CertsErr is set instead when the configuration could
	// not be gated or parsed.
	Certs    []CertRef
	CertsErr error
	// Servers is the configuration's server blocks (serversOf), nil when it
	// could not be parsed.
	Servers []nginxServer

	// Prefix is where the master resolves relative paths: its -p, else the
	// compiled prefix. PrefixGiven is whether it was started with -p, and
	// Globals what its -g holds that its commands repeat (startFrom).
	Prefix      string
	PrefixGiven bool
	Globals     string
	build       build
	// Cred is who the master runs as, nil for root (credOf).
	Cred *syscall.Credential
	// Signal is whether Reload is the master's own `nginx -s reload`, which
	// needs guard.
	Signal bool
	// Changed is the configuration's files edited since the master last
	// loaded them (changedSince).
	Changed []string
}

// CertRef is one ssl_certificate occurrence: where it was written, what it
// says, which file that turns out to be, and the key nginx pairs it with.
type CertRef struct {
	// PID is the master this occurrence was loaded by: occurrences are merged
	// across instances, so each has to say where it came from.
	PID      int
	File     string
	Line     int
	Value    string // exactly as written
	Resolved string // the real file, after prefix resolution and symlinks

	KeyValue    string
	KeyResolved string
	KeyLine     int
}

// Certificate is one real file, with every place it is referenced from.
type Certificate struct {
	Path string
	// Key is the key of the first occurrence. A certificate whose occurrences
	// disagree about the key carries a warning saying so (warnKeyConflict).
	Key string

	// SANs are the leaf's subject alternative names in the order the
	// extension encodes them, addresses interleaved and wildcards as written.
	SANs   []string
	SANErr error
	// KeyType is the leaf's key as a Certificate key type (wire.KeyTypes),
	// empty for any other algorithm.
	KeyType string
	// SHA256 is the hex SHA-256 of the leaf's DER, empty when the file holds
	// no certificate this could read.
	SHA256 string
	// LeafPEM and ChainPEM are the leaf and the certificates after it in the
	// file, which nginx sends in that order; empty with SHA256.
	LeafPEM, ChainPEM string

	Refs []CertRef
}

// analyze turns the instances into discovered Targets and warnings. Every
// certificate file the configurations name is a discovered Target, with the
// places that name it as references; what keeps one from being suggested is
// its own warnings, worded without its path, which the reader sees beside
// them, so the same situation reads the same for every certificate in it. The
// top-level warnings are left for what is not one certificate: an instance
// whose configuration could not be read, and a value that names no file.
//
// A warning is one whole message per language. What was found on the host
// (a path, a pid, a command, a location) and what nginx or a parser said in
// its own words go in as values and are the same in every language.
func analyze(found []instance) ([]DiscoveredTarget, []l10n.Text) {
	sort.Slice(found, func(i, j int) bool { return found[i].PID < found[j].PID })
	targets, warnings := []DiscoveredTarget{}, []l10n.Text{}
	masters := map[int]*instance{}
	var refs []CertRef
	for i, in := range found {
		masters[in.PID] = &found[i]
		if in.CertsErr != nil {
			warnings = append(warnings, warnInstance(in))
			continue
		}
		for _, c := range in.Certs {
			c.PID = in.PID
			refs = append(refs, c)
		}
	}
	refs, notFiles := filesOnly(refs)
	warnings = append(warnings, notFiles...)
	for _, c := range group(refs) {
		// The commands of the first master that loads it: one that more
		// read is warned about, and a reader needs some value to see.
		in := masters[c.Refs[0].PID]
		t := DiscoveredTarget{
			Settings: map[string]string{
				SettingCertificate: c.Path,
				SettingKey:         c.Key,
				SettingTest:        in.Test,
				SettingReload:      in.Reload,
			},
			ExtraData:  []ExtraDatum{},
			References: referencesOf(c.Refs),
			Warnings:   warningsOf(c, found, in),
		}
		if len(t.References) > plugincontract.MaxReferences {
			// The answer would be refused whole; a move of this certificate is
			// refused instead, since its confirmed references would not be
			// all of them.
			t.References = t.References[:plugincontract.MaxReferences]
		}
		// What the file itself says, absent when nothing could be read from
		// it.
		if c.SANErr == nil || c.KeyType != "" || c.SHA256 != "" {
			domains := c.SANs
			if domains == nil {
				domains = []string{}
			}
			t.Certificate = &DiscoveredCertificate{Domains: domains, KeyType: c.KeyType, SHA256: c.SHA256}
			if c.SHA256 != "" {
				t.Certificate.CertificatePem, t.Certificate.ChainPem = c.LeafPEM, c.ChainPEM
			}
		}
		targets = append(targets, t)
	}
	targets, warnings = capped(targets, warnings)
	budgetPEM(targets)
	return targets, warnings
}

// referencesOf is every directive the occurrences name a file with, once each:
// the ssl_certificate and, when it names a file, the ssl_certificate_key nginx
// pairs with it. Sorted by file and line, so two runs compare equal. relocate
// finds the references a move changes with this too, so what it changes is
// what discovery reported.
func referencesOf(refs []CertRef) []plugincontract.Reference {
	seen := map[plugincontract.Reference]bool{}
	out := []plugincontract.Reference{}
	add := func(r plugincontract.Reference) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, r := range refs {
		add(plugincontract.Reference{Setting: SettingCertificate, File: r.File, Line: r.Line, Value: r.Value})
		if r.KeyValue != "" && !notAFile(r.KeyValue, true) {
			add(plugincontract.Reference{Setting: SettingKey, File: r.File, Line: r.KeyLine, Value: r.KeyValue})
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

// warningsOf is everything that keeps a certificate from being suggested,
// each finding a warning of its own, once.
func warningsOf(c Certificate, found []instance, in *instance) []l10n.Text {
	var out []l10n.Text
	if w := warnShared(c, found); len(w) != 0 {
		out = append(out, w)
	}
	for _, r := range c.Refs[1:] {
		if r.KeyResolved != c.Key {
			out = append(out, warnKeyConflict(c))
			break
		}
	}
	for _, r := range c.Refs {
		if r.KeyValue != "" && notAFile(r.KeyValue, true) {
			out = append(out, T("nginx.problem.key_not_a_file",
				"Its key `{value}` (`{at}`) is not the name of one file (it holds a variable, or starts with `data:`, `engine:` or `store:`), so a Deployment has no file to write it to.",
				"value", shorten(r.KeyValue), "at", fmt.Sprintf("pid %d:%s:%d", r.PID, r.File, r.KeyLine)))
		}
	}
	if errors.Is(c.SANErr, pemfile.ErrNoCertificate) {
		out = append(out, T("nginx.problem.no_certificate",
			"It holds no PEM certificate, so its names cannot be read."))
	} else if c.SANErr != nil {
		out = append(out, T("nginx.problem.names_unreadable",
			"Its names could not be read: {error}.", "error", c.SANErr))
	}
	out = append(out, problemsOf(c, in)...)
	return dedupe(out)
}

// dedupe drops a warning equal to an earlier one, which two occurrences of
// one finding produce.
func dedupe(in []l10n.Text) []l10n.Text {
	out := []l10n.Text{}
	seen := map[string]bool{}
	for _, w := range in {
		if k := w.In(l10n.English); !seen[k] {
			seen[k] = true
			out = append(out, w)
		}
	}
	return out
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
	return targets, append(warnings, T("nginx.warning.too_many",
		"{count} more certificates were found and are not reported, because one answer reports at most {max}.",
		"count", left, "max", plugincontract.MaxDiscoveredTargets))
}

func or(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// warnInstance describes a master whose configuration gave no certificates,
// by why: it has no configuration this could find, nginx itself refuses the
// one it has, or the parser could not read it.
func warnInstance(in instance) l10n.Text {
	var rejected *rejectedError
	switch {
	case errors.Is(in.CertsErr, errNoConfiguration):
		return T("nginx.warning.no_configuration",
			"`pid {pid}` (`{exe}`): no configuration path known for this instance",
			"pid", in.PID, "exe", in.Exe)
	case errors.As(in.CertsErr, &rejected) && rejected.reason == "":
		return T("nginx.warning.configuration_rejected_no_reason",
			"`pid {pid}` (`{exe}`, config `{config}`): nginx rejects this configuration, so it was not parsed: configuration test failed",
			"pid", in.PID, "exe", in.Exe, "config", in.ConfigPath)
	case rejected != nil:
		return T("nginx.warning.configuration_rejected",
			"`pid {pid}` (`{exe}`, config `{config}`): nginx rejects this configuration, so it was not parsed: {reason}",
			"pid", in.PID, "exe", in.Exe, "config", in.ConfigPath, "reason", rejected.reason)
	}
	return T("nginx.warning.configuration_unreadable",
		"`pid {pid}` (`{exe}`, config `{config}`): {error}",
		"pid", in.PID, "exe", in.Exe, "config", in.ConfigPath, "error", in.CertsErr)
}

// warnShared describes a certificate file read by more than one master, or
// returns no text when exactly one reads it. Such a file is not suggested: a
// renewal that writes it is complete only once every master that reads it has
// been reloaded, and there is no single reload command for that. The warning
// recommends the structural way out.
func warnShared(c Certificate, found []instance) l10n.Text {
	// Instances in the order the references list them, each once, with the
	// places in each that name the file.
	var pids []int
	where := map[int][]string{}
	for _, r := range c.Refs {
		if _, seen := where[r.PID]; !seen {
			pids = append(pids, r.PID)
		}
		where[r.PID] = append(where[r.PID], fmt.Sprintf("`%s:%d`", r.File, r.Line))
	}
	if len(pids) < 2 {
		return nil
	}
	reload := map[int]string{}
	for _, in := range found {
		reload[in.PID] = in.Reload
	}
	// Each instance in the list is worded ("reloaded with", "at"), so the
	// list is built once per language rather than passed in as one value.
	return perLanguage(func(p l10n.Printer) string {
		var parts []string
		for _, pid := range pids {
			parts = append(parts, p.T("nginx.warning.shared_certificate.instance",
				"`pid {pid}`, reloaded with `{reload}`, at {locations}",
				"pid", pid, "reload", reload[pid], "locations", strings.Join(where[pid], ", ")))
		}
		return p.T("nginx.warning.shared_certificate",
			"It is read by {count} nginx instances ({instances}). A renewal written there takes effect "+
				"only in the instances reloaded afterwards, and the rest keep serving the previous certificate "+
				"from memory while the file on disk no longer shows it. Give each instance its own copy of the "+
				"certificate and key under a path only it reads, so that each can be renewed and reloaded on its own.",
			"count", len(pids), "instances", strings.Join(parts, "; "))
	})
}

// warnKeyConflict describes a certificate whose occurrences name different key
// files. It points at the ssl_certificate_key lines rather than the
// ssl_certificate ones, since those are what have to be reconciled.
func warnKeyConflict(c Certificate) l10n.Text {
	// One entry per distinct key file, in the order first seen, each with the
	// places that name it.
	var order []string
	where := map[string][]string{}
	for _, r := range c.Refs {
		if _, seen := where[r.KeyResolved]; !seen {
			order = append(order, r.KeyResolved)
		}
		where[r.KeyResolved] = append(where[r.KeyResolved], fmt.Sprintf("`pid %d` `%s:%d`", r.PID, r.File, r.KeyLine))
	}
	same := hostfile.SameContent(order)
	return perLanguage(func(p l10n.Printer) string {
		var parts []string
		for _, k := range order {
			parts = append(parts, p.T("nginx.warning.key_conflict.key",
				"`{key}` (at {locations})",
				"key", k, "locations", strings.Join(where[k], ", ")))
		}
		// Two whole messages rather than one sentence with advice appended:
		// which advice applies changes what the reader is being told.
		if same {
			return p.T("nginx.warning.key_conflict.same_bytes",
				"It is used with {count} different key files: {keys}. "+
					"All of these keys hold the same bytes, so point every one of them at a single "+
					"file: a renewal that writes only one leaves the others stale, and the next reload "+
					"then fails on a key that no longer matches its certificate.",
				"count", len(order), "keys", strings.Join(parts, "; "))
		}
		return p.T("nginx.warning.key_conflict.different",
			"It is used with {count} different key files: {keys}. "+
				"The keys differ, so at least one of these servers is not running the configuration "+
				"on disk: nginx refuses a certificate and key that do not match.",
			"count", len(order), "keys", strings.Join(parts, "; "))
	})
}

// errNoConfiguration is a master whose configuration file could not be told
// from its command line or its binary.
var errNoConfiguration = errors.New("no configuration path known for this instance")

// certificates parses one instance's configuration and returns every
// ssl_certificate in it.
//
// The parsing is nginx-go-crossplane's, NGINX's own Go port of crossplane,
// rather than a grep, because a line-oriented scan is wrong in three ways: a
// whole server block may sit on one physical line; an `include` may pull in
// files from anywhere; and a `#` comment or an unreferenced snippet can carry
// an ssl_certificate that nginx never loads.
//
// It parses the files rather than asking the running master, which is a real
// limitation. `nginx -T` prints only file contents, so it cannot attribute a
// directive to a file and line, which a tool that later has to edit a
// certificate path needs, and it cannot show anything injected with -g either.
func certificates(gate func(exe, config string) error, exe, config string) ([]CertRef, error) {
	if config == "" {
		return nil, errNoConfiguration
	}
	if err := gate(exe, config); err != nil {
		return nil, err
	}
	blocks, err := blocksOf(config)
	var out []CertRef
	for _, b := range blocks {
		out = append(out, pair(b)...)
	}
	return out, err
}

// blocksOf parses a configuration and returns every context that declares an
// ssl_certificate, with every path resolved: pairing reads the files to learn
// their algorithms, and a path cannot be opened until it is absolute. Parse
// errors are reported per file and do not fail the payload, so the first one
// is returned beside what did parse, rather than letting a half-parsed
// configuration look complete.
func blocksOf(config string) ([]block, error) {
	payload, err := crossplane.Parse(config, &crossplane.ParseOptions{})
	if err != nil {
		return nil, err
	}
	var blocks []block
	for _, f := range payload.Config {
		collect(f.Parsed, f.File, &blocks)
	}
	for bi := range blocks {
		for i := range blocks[bi].certs {
			blocks[bi].certs[i].resolved, _ = resolve(blocks[bi].certs[i].value, config)
		}
		for i := range blocks[bi].keys {
			blocks[bi].keys[i].resolved, _ = resolve(blocks[bi].keys[i].value, config)
		}
	}
	if len(payload.Errors) > 0 {
		return blocks, fmt.Errorf("%s", payload.Errors[0].Error)
	}
	return blocks, nil
}

// collect walks the directive tree, descending into every block, because
// ssl_certificate is valid at http, server and (since 1.15) stream level, and
// nothing guarantees the depth it appears at.
//
// Directives are gathered per block and paired afterwards, because pairing
// needs the files themselves and those cannot be read until the paths have been
// resolved. See pair for the rule.
func collect(dirs crossplane.Directives, file string, out *[]block) {
	b := block{file: file}
	for _, d := range dirs {
		if len(d.Args) == 0 {
			continue
		}
		switch d.Directive {
		case "ssl_certificate":
			b.certs = append(b.certs, ref{line: d.Line, value: d.Args[0]})
		case "ssl_certificate_key":
			b.keys = append(b.keys, ref{line: d.Line, value: d.Args[0]})
		}
	}
	if len(b.certs) > 0 {
		*out = append(*out, b)
	}
	for _, d := range dirs {
		if d.Block != nil {
			collect(d.Block, file, out)
		}
	}
}

// ref is one directive: where it is and what it says, plus what that resolves
// to once the path has been made absolute and dereferenced.
type ref struct {
	line     int
	value    string
	resolved string
}

// block is the ssl_certificate and ssl_certificate_key directives of one
// context, in the order written.
type block struct {
	file  string
	certs []ref
	keys  []ref
}

// pair matches each certificate in a block with the key nginx will actually use
// for it.
//
// nginx pairs by position (ngx_ssl_certificates walks cert[i] with key[i]), but
// OpenSSL keeps one slot per key algorithm: SSL_CTX_use_certificate files a
// certificate by its own type and SSL_CTX_use_PrivateKey files a key by its own
// type. A block declaring an ECDSA and an RSA certificate with the two keys in
// the opposite order is therefore accepted and works, and nginx does not warn.
//
// So certificates and keys are grouped by algorithm and paired within each
// group. Where every certificate in a block shares one algorithm this is
// exactly positional pairing, and there the order does matter: two RSA
// certificates with their keys swapped is a hard failure at load, verified as
// "key values mismatch".
//
// Position is the fallback whenever an algorithm cannot be determined (an
// unreadable file, an unsupported key type), since it is what nginx wrote down
// and is right whenever the block is uniform.
func pair(b block) []CertRef {
	certAlg := make([]x509.PublicKeyAlgorithm, len(b.certs))
	keyAlg := make([]x509.PublicKeyAlgorithm, len(b.keys))
	known := true
	for i, c := range b.certs {
		if certAlg[i] = certificateAlgorithm(c.resolved); certAlg[i] == x509.UnknownPublicKeyAlgorithm {
			known = false
		}
	}
	for i, k := range b.keys {
		if keyAlg[i] = keyAlgorithm(k.resolved); keyAlg[i] == x509.UnknownPublicKeyAlgorithm {
			known = false
		}
	}

	// Which key each certificate gets, as an index into b.keys.
	take := make([]int, len(b.certs))
	for i := range take {
		take[i] = -1
	}
	if known {
		next := map[x509.PublicKeyAlgorithm]int{}
		for i, alg := range certAlg {
			for j := next[alg]; j < len(b.keys); j++ {
				if keyAlg[j] == alg {
					take[i] = j
					next[alg] = j + 1
					break
				}
			}
		}
	} else {
		for i := range b.certs {
			if i < len(b.keys) {
				take[i] = i
			}
		}
	}

	out := make([]CertRef, 0, len(b.certs))
	for i, c := range b.certs {
		r := CertRef{File: b.file, Line: c.line, Value: c.value, Resolved: c.resolved}
		// A block with fewer keys than certificates is one nginx refuses to
		// start on. Leaving the key empty reports that rather than pairing
		// something arbitrary.
		if j := take[i]; j >= 0 {
			r.KeyValue = b.keys[j].value
			r.KeyResolved = b.keys[j].resolved
			r.KeyLine = b.keys[j].line
		}
		out = append(out, r)
	}
	return out
}

// certificateAlgorithm reports the public key algorithm of a certificate's leaf.
func certificateAlgorithm(path string) x509.PublicKeyAlgorithm {
	leaf, err := leafOf(path)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	return leaf.PublicKeyAlgorithm
}

// keyAlgorithm reports the algorithm of a private key file, in any of the
// three encodings nginx accepts; unknown for an encrypted one.
func keyAlgorithm(path string) x509.PublicKeyAlgorithm {
	b, err := os.ReadFile(path)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	return pemfile.KeyAlgorithm(b)
}

// resolve turns an ssl_certificate value into the real file it names.
//
// First the path is made absolute against the right base, which is NOT the
// prefix compiled into the binary or given with -p: the ssl_certificate handler
// calls ngx_conf_full_name(cf->cycle, file, 1), and that last argument selects
// cycle->conf_prefix, the directory holding the file named by -c. On the test
// host the packaged binary's prefix is /usr/share/nginx while one instance runs
// it against a config in /opt/nginx-third, and resolving against the prefix
// sends the lookup to a path nginx never opens.
//
// Then symlinks are evaluated, which also collapses ".", ".." and doubled
// slashes. Neither step substitutes for the other: EvalSymlinks alone leaves a
// relative path relative, and lexical cleaning alone cannot see through the
// live/archive symlink farm certbot creates.
func resolve(value, config string) (string, error) {
	p := value
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(config), p)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		// A certificate nginx is serving must exist, so this is worth
		// surfacing rather than swallowing. The lexically cleaned path is
		// still the best answer available, and keying on it at least groups
		// the occurrences that agree.
		return filepath.Clean(p), err
	}
	return real, nil
}

// group collects occurrences by the file they resolve to, so a certificate
// named several ways is reported once with every place it is used. Sorted by
// path, and by master, file and line within each, so two runs of the tool can
// be compared. A certificate whose occurrences name different keys keeps the
// first one's key, and a warning (warnKeyConflict) says it is not the only.
func group(refs []CertRef) []Certificate {
	byPath := map[string][]CertRef{}
	for _, r := range refs {
		byPath[r.Resolved] = append(byPath[r.Resolved], r)
	}
	out := make([]Certificate, 0, len(byPath))
	for path, rs := range byPath {
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].PID != rs[j].PID {
				return rs[i].PID < rs[j].PID
			}
			if rs[i].File != rs[j].File {
				return rs[i].File < rs[j].File
			}
			return rs[i].Line < rs[j].Line
		})
		c := Certificate{Path: path, Key: rs[0].KeyResolved, Refs: rs}
		c.SANs, c.SANErr = sans(path)
		if b, err := os.ReadFile(path); err == nil {
			c.LeafPEM, c.ChainPEM = pemfile.LeafAndChain(b)
		}
		if der, err := leafDER(path); err == nil {
			sum := sha256.Sum256(der)
			c.SHA256 = hex.EncodeToString(sum[:])
			if leaf, err := x509.ParseCertificate(der); err == nil {
				c.KeyType = wire.KeyTypeOf(leaf.PublicKey)
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// sans reads a certificate file and returns the subject alternative names of
// its leaf, in the order the extension encodes them. Only the first certificate
// in the file is read: an ssl_certificate commonly points at a fullchain, where
// the leaf comes first, and the issuers' names are not what this server answers
// for.
//
// The extension is decoded here rather than read from crypto/x509's DNSNames
// and IPAddresses, which are two separate slices: a SAN encoded DNS, IP, DNS
// comes back as two names and one address with nothing recording that the
// address sat between them. A certificate on the test host encoded in exactly
// that order proved appending the addresses after the names wrong.
//
// Only dNSName and iPAddress are reported. The other GeneralName choices
// (rfc822Name, uniformResourceIdentifier, otherName) are valid in the same
// extension but do not name a TLS server.
func sans(path string) ([]string, error) {
	leaf, err := leafOf(path)
	if err != nil {
		return nil, err
	}
	return pemfile.GeneralNames(leaf)
}

// leafOf parses the first certificate in a PEM file: ssl_certificate commonly
// points at a fullchain where the leaf comes first, and an issuer is neither
// what the server answers for nor what its key belongs to.
func leafOf(path string) (*x509.Certificate, error) {
	der, err := leafDER(path)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// leafDER is the DER of the first certificate in a PEM file, unparsed, so a
// leaf crypto/x509 refuses (a negative serial) still has a fingerprint.
func leafDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// The error names no path: it becomes a warning shown beside the path.
	return pemfile.LeafDER(b)
}
