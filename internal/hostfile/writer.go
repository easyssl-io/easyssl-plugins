package hostfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Cred is a filesystem uid and gid and the supplementary groups: what the
// kernel checks when a process opens a file.
type Cred struct {
	UID, GID uint32
	Groups   []uint32
}

// IsRoot reports the root user.
func (c Cred) IsRoot() bool { return c.UID == 0 }

// Sys is c for exec's SysProcAttr.
func (c Cred) Sys() *syscall.Credential {
	g := c.Groups
	if g == nil {
		g = []uint32{}
	}
	return &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: g}
}

// WriteRequest is what WriteAs sends the child it starts under a file owner's
// credentials.
type WriteRequest struct {
	Path   string `json:"path"`
	Data   []byte `json:"data"`
	Remove bool   `json:"remove"`
}

// Write carries out a WriteRequest in this process, with whatever credentials
// it was started with. A Plugin's main calls it for the operation it passes
// WriteAs.
func Write(req WriteRequest) error {
	if req.Remove {
		return os.Remove(req.Path)
	}
	return Replace(req.Path, req.Data)
}

// WriteAs replaces or removes a file with the credentials of the user its
// directory belongs to (WriterFor), so in a directory a user controls the
// Plugin can only do what that user could already do. Running as root there
// would let the user swap the path for a symlink to /etc/shadow, say, between
// the Plugin's checks and its write, and have root overwrite it. The work is
// done by a child: this executable run again with op, under those
// credentials, because changing the filesystem ids inside a Go process only
// changes one of its threads. op is the Plugin's own operation that reads a
// WriteRequest from stdin and calls Write.
func WriteAs(op, path string, data []byte, remove bool) error {
	w, err := WriterFor(path)
	if err != nil {
		return err
	}
	req := WriteRequest{Path: path, Data: data, Remove: remove}
	if w == nil || w.UID == uint32(os.Geteuid()) {
		// Root's own directories, or this process already is the writer.
		return Write(req)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	cmd := exec.Command(self, op)
	cmd.Stdin = bytes.NewReader(body)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: w.Sys()}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("as uid %d: %s", w.UID, strings.TrimSpace(string(out)))
	}
	return nil
}

// ErrUnsafe is a path a file cannot be written to safely.
var ErrUnsafe = errors.New("unsafe path")

// WriterFor decides who writes a file: nil for root, or the user that owns a
// directory on the way to it. Every directory from / to the file must belong
// to root or to that one user, and be writable by nobody else, or a third
// party could change what the path leads to. Root-owned directories below a
// user's one are fine, because the user is who writes. In a user's directory
// a file that exists must belong to that user, who cannot give a new file
// someone else's ownership. Directories that do not exist yet are created by
// the writer, so they are its own.
func WriterFor(path string) (*Cred, error) {
	dir := filepath.Dir(path)
	var owner uint32
	chain := ancestors(dir)
	for i, d := range chain {
		info, err := os.Lstat(d)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() {
			return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafe, d)
		}
		// A sticky directory such as /tmp lets others add entries but not
		// replace one they do not own, so it is safe on the way, where the
		// next directory's owner is checked in turn, and not as the file's own
		// directory, where others could add the names the write uses. A
		// missing directory below it is one others could create first, so
		// there the sticky one counts as the file's own.
		last := i == len(chain)-1
		if !last {
			if _, err := os.Lstat(chain[i+1]); errors.Is(err, os.ErrNotExist) {
				last = true
			}
		}
		sticky := info.Mode()&os.ModeSticky != 0 && !last
		if info.Mode().Perm()&0o022 != 0 && !sticky {
			return nil, fmt.Errorf("%w: %s can be written by users other than its owner", ErrUnsafe, d)
		}
		if st.Uid != 0 {
			if owner != 0 && st.Uid != owner {
				return nil, fmt.Errorf("%w: %s belongs to uid %d, inside a directory of uid %d", ErrUnsafe, d, st.Uid, owner)
			}
			owner = st.Uid
		}
	}
	if owner == 0 {
		// Only root can change anything on the way, so root writes, and gives
		// the new file whatever owner the old one had.
		return nil, nil
	}
	if m, err := MetaOf(path); err == nil && m.UID != owner {
		return nil, fmt.Errorf("%w: %s belongs to uid %d, but its directory to uid %d", ErrUnsafe, path, m.UID, owner)
	}
	return CredOfUser(owner)
}

// ancestors lists / and every directory down to dir.
func ancestors(dir string) []string {
	dir = filepath.Clean(dir)
	out := []string{dir}
	for d := dir; d != "/" && d != "."; {
		d = filepath.Dir(d)
		out = append(out, d)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// CredOfUser is a user's uid, primary gid and supplementary groups.
func CredOfUser(uid uint32) (*Cred, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fmt.Errorf("looking up uid %d: %w", uid, err)
	}
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	c := &Cred{UID: uid, GID: uint32(gid)}
	ids, _ := u.GroupIds()
	for _, s := range ids {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			c.Groups = append(c.Groups, uint32(n))
		}
	}
	return c, nil
}

// MaxFile bounds what is read from a certificate or key file.
const MaxFile = 1 << 20

// ReadSafely reads a file without following a symlink in its last component,
// and only when it belongs to whoever writes it (WriterFor), so a path a user
// swapped for a link to another user's file is refused instead of read as
// root and later written back into the user's directory. A missing file is
// nil with no error.
func ReadSafely(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	w, err := WriterFor(path)
	if err != nil {
		return nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if w != nil && st.Uid != w.UID || st.Nlink > 1 {
			return nil, fmt.Errorf("%w: %s changed owner or gained a hard link since it was checked", ErrUnsafe, path)
		}
	}
	return io.ReadAll(io.LimitReader(f, MaxFile))
}
