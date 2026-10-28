package ops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// oidSubjectAltName is 2.5.29.17, and the two GeneralName tags encodeSANs
// writes (RFC 5280 4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

const (
	tagDNSName   = 2
	tagIPAddress = 7
)

// material is one generated certificate and its key, as PEM.
type material struct {
	cert, key string
}

// issue makes a self-signed certificate of the given key type, with the SANs
// in the order given: an entry parsing as an IP address is encoded as one,
// which is how a test reproduces the interleaved DNS, IP, DNS case.
func issue(t *testing.T, keyType string, sans ...string) material {
	t.Helper()
	var key crypto.Signer
	var err error
	if keyType == "rsa" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	var sanExt []byte
	if len(sans) > 0 {
		sanExt = encodeSANs(t, sans)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Value: sanExt}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return material{
		cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})),
	}
}

// encodeSANs builds a SubjectAltName extension value in exactly this order,
// which x509.Certificate's separate DNSNames and IPAddresses cannot express.
func encodeSANs(t *testing.T, sans []string) []byte {
	t.Helper()
	var body []byte
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			body = append(body, derTLV(0x80|tagIPAddress, ip)...)
		} else {
			body = append(body, derTLV(0x80|tagDNSName, []byte(s))...)
		}
	}
	return derTLV(0x30, body)
}

func derTLV(tag byte, v []byte) []byte {
	if len(v) < 128 {
		return append([]byte{tag, byte(len(v))}, v...)
	}
	return append([]byte{tag, 0x82, byte(len(v) >> 8), byte(len(v))}, v...)
}

// tree writes files under a temporary root: a value "->x" makes a symlink to
// x, anything else is the file's content.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := ownedDir(t)
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if len(content) > 2 && content[:2] == "->" {
			if err := os.Symlink(content[2:], full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Writable by their owner alone, whatever the umask, or every file under
	// them is unsafe to replace (hostfile.WriterFor) and nothing is suggested.
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			err = os.Chmod(p, 0o755)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// accept is a gate that passes every configuration, standing in for `nginx -t`.
func accept(string, string) error { return nil }

// load is one instance at pid with its configuration parsed, as scan builds it.
func load(t *testing.T, pid int, config string) instance {
	t.Helper()
	in := instance{PID: pid, Exe: "/usr/sbin/nginx", ConfigPath: config,
		Test: "/usr/sbin/nginx -t", Reload: "systemctl reload nginx.service"}
	in.Certs, in.CertsErr = certificates(accept, in.Exe, config)
	if in.CertsErr == nil {
		in.Servers, _ = serversOf(config)
	}
	return in
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o644) }

// ownedDir is a fresh directory only its owner can write, as
// hostfile.WriterFor requires of every directory on the way to a file.
func ownedDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}
