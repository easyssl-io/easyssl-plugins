package ops

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	crossplane "github.com/nginxinc/nginx-go-crossplane"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Discovery, in two halves. scan.go finds the running nginx masters and asks
// each for its reload and test commands; this file parses what each one loads
// and turns it into discovered Targets and warnings. The split is what lets the
// tests run every configuration case against real files without a running
// nginx.

// Discover answers with the declarations and what this host's nginx serves.
// A host with no nginx, or one this Plugin cannot inspect, answers with the
// declarations and no discovered Targets: discover never fails for what it
// finds.
func Discover() DiscoverResponse {
	resp := DiscoverResponse{
		ContractVersion: plugincontractVersion,
		Name:            Name,
		Version:         Version(),
		Description: T("nginx.description",
			"Installs Certificates into nginx. It finds the certificates every running nginx serves, "+
				"and installs a new one by writing the files, testing the configuration with `nginx -t` "+
				"and reloading only when that passes."),
		Settings:          declarations(),
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
	// disagree about the key is not reported at all but warned about, since
	// reporting one key would be true of only some of its uses.
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

	Refs []CertRef
}

// analyze turns the instances into discovered Targets and warnings. Every
// discovered Target belongs to exactly one master, because a file read by two
// leaves the list (warnShared), so "its reload" is well defined.
//
// A warning is one whole message per language. What was found on the host
// (a path, a pid, a command, a location) and what nginx or a parser said in
// its own words go in as values and are the same in every language.
func analyze(found []instance) ([]DiscoveredTarget, []l10n.Text) {
	sort.Slice(found, func(i, j int) bool { return found[i].PID < found[j].PID })
	targets, warnings := []DiscoveredTarget{}, []l10n.Text{}
	reload, test := map[int]string{}, map[int]string{}
	var refs []CertRef
	for _, in := range found {
		reload[in.PID], test[in.PID] = in.Reload, in.Test
		if in.CertsErr != nil {
			warnings = append(warnings, warnInstance(in))
			continue
		}
		for _, c := range in.Certs {
			c.PID = in.PID
			refs = append(refs, c)
		}
	}
	grouped, conflicts := group(refs)
	for _, c := range grouped {
		if w := warnShared(c, found); len(w) != 0 {
			warnings = append(warnings, w)
			continue
		}
		t := DiscoveredTarget{
			PluginSettings: map[string]string{
				SettingCertificate: c.Path,
				SettingKey:         c.Key,
				SettingTest:        test[c.Refs[0].PID],
				SettingReload:      reload[c.Refs[0].PID],
			},
		}
		// What the file itself says, absent when nothing could be read from
		// it: the installation point is reported regardless, since it works
		// whatever the parser thinks of the file.
		if c.SANErr == nil || c.KeyType != "" || c.SHA256 != "" {
			domains := c.SANs
			if domains == nil {
				domains = []string{}
			}
			t.Certificate = &DiscoveredCertificate{Domains: domains, KeyType: c.KeyType, SHA256: c.SHA256}
		}
		if errors.Is(c.SANErr, errNoCertificate) {
			warnings = append(warnings, T("nginx.warning.no_certificate",
				"`{path}`: its names could not be read, so none are reported: the file holds no PEM certificate",
				"path", c.Path))
		} else if c.SANErr != nil {
			warnings = append(warnings, T("nginx.warning.names_unreadable",
				"`{path}`: its names could not be read, so none are reported: {error}",
				"path", c.Path, "error", c.SANErr))
		}
		var lines []string
		for _, r := range c.Refs {
			lines = append(lines, fmt.Sprintf("`pid %d:%s:%d`", r.PID, r.File, r.Line))
		}
		t.PluginExtraData = []ExtraDatum{{Label: T("nginx.extra.locations", "Locations"), Value: strings.Join(lines, "\n")}}
		targets = append(targets, t)
	}
	for _, c := range conflicts {
		warnings = append(warnings, warnKeyConflict(c))
	}
	return targets, warnings
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
// returns no text when exactly one reads it. Such a file is kept out of the list
// entirely: a renewal that writes it is complete only once every master that
// reads it has been reloaded, and there is no single reload command for that,
// so an entry naming the file would look like one thing to renew and be wrong.
// The way out is structural, which is what the warning recommends.
func warnShared(c Certificate, found []instance) l10n.Text {
	// Instances in the order the locations list them, each once, with the
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
			"`{path}` is read by {count} nginx instances ({instances}) and is not listed. A renewal "+
				"written there takes effect only in the instances reloaded afterwards, and the rest keep "+
				"serving the previous certificate from memory while the file on disk no longer shows it. "+
				"Give each instance its own copy of the certificate and key under a path only it reads, "+
				"so that each can be renewed and reloaded on its own.",
			"path", c.Path, "count", len(pids), "instances", strings.Join(parts, "; "))
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
	same := sameContent(order)
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
				"`{path}` is used with {count} different key files: {keys}. "+
					"All of these keys hold the same bytes, so point every one of them at a single "+
					"file: a renewal that writes only one leaves the others stale, and the next reload "+
					"then fails on a key that no longer matches its certificate.",
				"path", c.Path, "count", len(order), "keys", strings.Join(parts, "; "))
		}
		return p.T("nginx.warning.key_conflict.different",
			"`{path}` is used with {count} different key files: {keys}. "+
				"The keys differ, so at least one of these servers is not running the configuration "+
				"on disk: nginx refuses a certificate and key that do not match.",
			"path", c.Path, "count", len(order), "keys", strings.Join(parts, "; "))
	})
}

// sameContent reports whether every path holds identical bytes. A key is a few
// kilobytes, so this compares them rather than hashing.
func sameContent(paths []string) bool {
	if len(paths) < 2 {
		return true
	}
	first, err := os.ReadFile(paths[0])
	if err != nil {
		return false
	}
	for _, p := range paths[1:] {
		b, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(b, first) {
			return false
		}
	}
	return true
}

// errNoConfiguration is a master whose configuration file could not be told
// from its command line or its binary.
var errNoConfiguration = errors.New("no configuration path known for this instance")

// certificates parses one instance's configuration and returns every
// ssl_certificate in it.
//
// The parsing is nginx-go-crossplane's, NGINX's own Go port of crossplane,
// rather than a grep. Three properties of a real configuration make a
// line-oriented scan wrong, and all three are present on the test hosts: a
// whole server block may sit on one physical line, so a directive is not at the
// start of one; an `include` may pull in files from anywhere, so the set of
// files is not knowable without resolving them; and a `#` comment or an
// unreferenced snippet can carry an ssl_certificate that nginx never loads, so
// the filesystem holds more than the configuration does.
//
// It parses the files rather than asking the running master, which is worth
// stating because it is a real limitation: `nginx -T` would be nginx's own
// resolution of the same question, but it prints only file contents, so it
// cannot attribute a directive to a file and line, and it cannot show anything
// injected with -g either. Attribution is what a tool that later has to EDIT a
// certificate path needs, so crossplane is the better trade here.
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
// nginx itself pairs by position — ngx_ssl_certificates walks cert[i] with
// key[i] — but position is not the whole rule, because what nginx hands those
// pairs to is not positional. OpenSSL keeps one slot per key algorithm:
// SSL_CTX_use_certificate files a certificate by its own type and
// SSL_CTX_use_PrivateKey files a key by its own type. A block declaring an
// ECDSA and an RSA certificate with the two keys in the opposite order is
// therefore accepted and works, because each file lands in the slot for its
// algorithm and the crossing cancels out. nginx does not warn, and cannot:
// from its point of view nothing is wrong.
//
// So certificates and keys are grouped by algorithm and paired within each
// group, which is what OpenSSL ends up doing. Where every certificate in a
// block shares one algorithm this is exactly positional pairing, and there the
// order does matter: two RSA certificates with their keys swapped is a hard
// failure at load, verified as "key values mismatch".
//
// Position is the fallback whenever an algorithm cannot be determined — an
// unreadable file, an unsupported key type — since it is what nginx wrote down
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

// keyAlgorithm reports the algorithm of a private key file, trying the three
// encodings nginx accepts.
func keyAlgorithm(path string) x509.PublicKeyAlgorithm {
	b, err := os.ReadFile(path)
	if err != nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			return algorithmOf(k)
		}
		if _, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return x509.RSA
		}
		if _, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			return x509.ECDSA
		}
	}
	return x509.UnknownPublicKeyAlgorithm
}

func algorithmOf(k any) x509.PublicKeyAlgorithm {
	switch k.(type) {
	case *rsa.PrivateKey:
		return x509.RSA
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	case ed25519.PrivateKey:
		return x509.Ed25519
	}
	return x509.UnknownPublicKeyAlgorithm
}

// resolve turns an ssl_certificate value into the real file it names.
//
// Two steps, and both are needed. First the path is made absolute against the
// right base, which is NOT the prefix compiled into the binary or given with
// -p: nginx has two, and ssl_certificate uses the second. Its handler calls
// ngx_conf_full_name(cf->cycle, file, 1), and that last argument selects
// cycle->conf_prefix — the directory holding the file named by -c. On the test
// host the two are genuinely different: the packaged binary's prefix is
// /usr/share/nginx while one instance runs it against a config in
// /opt/nginx-third, and resolving against the prefix sends the lookup to a
// path nginx never opens.
//
// Then symlinks are evaluated, which also collapses ".", ".." and doubled
// slashes. Both halves are required and neither substitutes for the other:
// EvalSymlinks alone leaves a relative path relative, and lexical cleaning
// alone cannot see through the live/archive symlink farm certbot creates.
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
// path, and by file and line within each, so two runs of the tool can be
// compared.
func group(refs []CertRef) (kept, conflicts []Certificate) {
	byPath := map[string][]CertRef{}
	for _, r := range refs {
		byPath[r.Resolved] = append(byPath[r.Resolved], r)
	}
	kept = make([]Certificate, 0, len(byPath))
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
		conflict := false
		for _, r := range rs[1:] {
			if r.KeyResolved != c.Key {
				conflict = true
			}
		}
		if conflict {
			// Not listed at all: reporting one of the keys would state
			// something true of only some of this certificate's uses.
			conflicts = append(conflicts, c)
			continue
		}
		c.SANs, c.SANErr = sans(path)
		if der, err := leafDER(path); err == nil {
			sum := sha256.Sum256(der)
			c.SHA256 = hex.EncodeToString(sum[:])
			if leaf, err := x509.ParseCertificate(der); err == nil {
				c.KeyType = wire.KeyTypeOf(leaf.PublicKey)
			}
		}
		kept = append(kept, c)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Path < kept[j].Path })
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].Path < conflicts[j].Path })
	return kept, conflicts
}

// sans reads a certificate file and returns the subject alternative names of
// its leaf, in the order the extension encodes them.
//
// Only the first certificate in the file is read. An ssl_certificate commonly
// points at a fullchain, where the leaf comes first and the issuers follow, and
// the issuers' names are not what this server answers for.
//
// The extension is decoded here rather than read from crypto/x509's DNSNames
// and IPAddresses. Those are two separate slices, so the interleaving is lost
// the moment the certificate is parsed: a SAN encoded DNS, IP, DNS comes back
// as two names and one address with nothing recording that the address sat
// between them, and any reassembly is a guess. Appending the addresses after
// the names was that guess, and a certificate on the test host encoded in
// exactly that order proved it wrong.
//
// Only dNSName and iPAddress are reported. The other GeneralName choices —
// rfc822Name, uniformResourceIdentifier, otherName — are valid in the same
// extension but do not name a TLS server, and leaving them out keeps this a
// list of hostnames.
func sans(path string) ([]string, error) {
	leaf, err := leafOf(path)
	if err != nil {
		return nil, err
	}
	return generalNames(leaf)
}

// leafOf parses the first certificate in a PEM file.
//
// Only the first, because ssl_certificate commonly points at a fullchain where
// the leaf comes first and the issuers follow, and an issuer is neither what
// the server answers for nor what its key belongs to.
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
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue // a key or parameters sharing the file
		}
		return blk.Bytes, nil
	}
	return nil, fmt.Errorf("%w in %s", errNoCertificate, path)
}

// errNoCertificate is a file with no certificate in it, named apart from the
// errors a parser produces so its warning can be worded in every language.
var errNoCertificate = errors.New("no PEM certificate")

// oidSubjectAltName is 2.5.29.17.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// GeneralName context-specific tags, RFC 5280 4.2.1.6.
const (
	tagDNSName   = 2
	tagIPAddress = 7
)

// generalNames walks the SubjectAltName extension in encoding order.
func generalNames(leaf *x509.Certificate) ([]string, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			return nil, fmt.Errorf("subjectAltName: %w", err)
		}
		var out []string
		for rest := seq.Bytes; len(rest) > 0; {
			var v asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &v)
			if err != nil {
				return nil, fmt.Errorf("subjectAltName entry: %w", err)
			}
			switch v.Tag {
			case tagDNSName:
				out = append(out, string(v.Bytes))
			case tagIPAddress:
				// 4 bytes for IPv4, 16 for IPv6; anything else is not an
				// address and is left out rather than rendered as nonsense.
				if l := len(v.Bytes); l == net.IPv4len || l == net.IPv6len {
					out = append(out, net.IP(v.Bytes).String())
				}
			}
		}
		return out, nil
	}
	return nil, nil // no SubjectAltName extension at all
}
