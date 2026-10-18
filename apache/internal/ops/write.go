package ops

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

// Replacing a file so that only its content changes.
//
// A file is replaced by writing a temporary file beside it and renaming it over
// the old one, so a reader sees either file whole and never part of one. The
// rename creates a new inode, which carries nothing of the old file's metadata,
// so the temporary file is given the old file's owner, group and mode and every
// extended attribute (POSIX ACLs are the system.posix_acl_access attribute,
// the SELinux label is security.selinux), loses whatever it inherited that
// the old file lacks (a directory's default ACL), and is compared with the old
// file before the rename. A file the rename cannot replace faithfully is
// refused: one with more than one hard link, whose other names would keep the
// old content, and an immutable or append-only one.

// defaultMode is a new file's mode, when there is no file to copy one from.
const defaultMode os.FileMode = 0o600

// fileMeta is everything about a file except its content that a replacement
// keeps.
type fileMeta struct {
	mode   os.FileMode
	uid    uint32
	gid    uint32
	nlink  uint64
	xattrs map[string][]byte
}

func metaOf(path string) (fileMeta, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileMeta{}, err
	}
	m := fileMeta{mode: info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		m.uid, m.gid, m.nlink = st.Uid, st.Gid, uint64(st.Nlink)
	}
	if m.xattrs, err = xattrs(path); err != nil {
		return fileMeta{}, err
	}
	return m, nil
}

// differs names what makes two files' metadata differ, "" when nothing does.
func (a fileMeta) differs(b fileMeta) string {
	if a.mode != b.mode {
		return fmt.Sprintf("mode %04o instead of %04o", uint32(b.mode.Perm()), uint32(a.mode.Perm()))
	}
	if a.uid != b.uid || a.gid != b.gid {
		return fmt.Sprintf("owner %d:%d instead of %d:%d", b.uid, b.gid, a.uid, a.gid)
	}
	var names []string
	for k := range a.xattrs {
		names = append(names, k)
	}
	for k := range b.xattrs {
		if _, ok := a.xattrs[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		if !bytes.Equal(a.xattrs[k], b.xattrs[k]) {
			return fmt.Sprintf("extended attribute %s differs", k)
		}
	}
	return ""
}

// replaceFile puts data at path so that only the content changes, as described
// above. A path with no file yet gets a new file at defaultMode.
func replaceFile(path string, data []byte) error {
	old, err := metaOf(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existed {
		if err := replaceable(path, old); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".easyssl-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, defaultMode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // a no-op once the rename has succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if existed {
		if err := clone(tmp, old); err != nil {
			return fmt.Errorf("giving the new %s the old one's metadata: %w", path, err)
		}
		got, err := metaOf(tmp)
		if err != nil {
			return err
		}
		if d := old.differs(got); d != "" {
			return fmt.Errorf("the new %s would have %s, so it was not replaced", path, d)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// clone gives the file at tmp the metadata old describes. The extended
// attributes go first: setting system.posix_acl_access rewrites the group
// mode bits, so the mode is set last.
func clone(tmp string, old fileMeta) error {
	cur, err := metaOf(tmp)
	if err != nil {
		return err
	}
	if cur.uid != old.uid || cur.gid != old.gid {
		uid := int(old.uid)
		if os.Geteuid() != 0 {
			uid = -1 // only the group can change without root, and only to one of ours
		}
		if err := os.Lchown(tmp, uid, int(old.gid)); err != nil {
			return err
		}
	}
	for k, v := range old.xattrs {
		if err := setXattr(tmp, k, v); err != nil {
			return fmt.Errorf("extended attribute %s: %w", k, err)
		}
	}
	for k := range cur.xattrs {
		if _, ok := old.xattrs[k]; !ok {
			if err := removeXattr(tmp, k); err != nil {
				return fmt.Errorf("extended attribute %s the old file lacks: %w", k, err)
			}
		}
	}
	return os.Chmod(tmp, old.mode)
}

// replaceable refuses a file a rename cannot replace faithfully.
func replaceable(path string, m fileMeta) error {
	if m.nlink > 1 {
		return fmt.Errorf("%s has %d hard links, and replacing it would leave the other names with the previous content", path, m.nlink)
	}
	if immutable(path) {
		return fmt.Errorf("%s is immutable or append-only (chattr +i or +a), so it cannot be replaced", path)
	}
	return nil
}

// WriteFileRequest is what deploy sends the child it starts under a file
// owner's credentials (writeAs).
type WriteFileRequest struct {
	Path   string `json:"path"`
	Data   []byte `json:"data"`
	Remove bool   `json:"remove"`
}

// WriteFile carries out a WriteFileRequest in this process, with whatever
// credentials it was started with.
func WriteFile(req WriteFileRequest) error {
	if req.Remove {
		return os.Remove(req.Path)
	}
	return replaceFile(req.Path, req.Data)
}

// writeAs replaces or removes a file with the credentials of the user its
// directory belongs to (writerFor), so in a directory a user controls the
// Plugin can only do what that user could already do. Running as root there
// would let the user swap the path for a symlink to /etc/shadow, say, between
// the Plugin's checks and its write, and have root overwrite it. The work is
// done by a child: this executable run again with OpWriteFile, under those
// credentials, because changing the filesystem ids inside a Go process only
// changes one of its threads.
func writeAs(path string, data []byte, remove bool) error {
	w, err := writerFor(path)
	if err != nil {
		return err
	}
	req := WriteFileRequest{Path: path, Data: data, Remove: remove}
	if w == nil || w.UID == uint32(os.Geteuid()) {
		// Root's own directories, or this process already is the writer.
		return WriteFile(req)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	cmd := exec.Command(self, OpWriteFile)
	cmd.Stdin = bytes.NewReader(body)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: w.sys()}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("as uid %d: %s", w.UID, strings.TrimSpace(string(out)))
	}
	return nil
}

// errUnsafe is a path a file cannot be written to safely.
var errUnsafe = errors.New("unsafe path")

// writerFor decides who writes a file: nil for root, or the user that owns a
// directory on the way to it. Every directory from / to the file must belong
// to root or to that one user, and be writable by nobody else, or a third
// party could change what the path leads to. Root-owned directories below a
// user's one are fine, because the user is who writes. In a user's directory
// a file that exists must belong to that user, who cannot give a new file
// someone else's ownership.
func writerFor(path string) (*cred, error) {
	dir := filepath.Dir(path)
	var owner uint32
	chain := ancestors(dir)
	for i, d := range chain {
		info, err := os.Lstat(d)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() {
			return nil, fmt.Errorf("%w: %s is not a directory", errUnsafe, d)
		}
		// A sticky directory such as /tmp lets others add entries but not
		// replace one they do not own, so it is safe on the way, where the
		// next directory's owner is checked in turn, and not as the file's own
		// directory, where others could add the names the write uses.
		sticky := info.Mode()&os.ModeSticky != 0 && i < len(chain)-1
		if info.Mode().Perm()&0o022 != 0 && !sticky {
			return nil, fmt.Errorf("%w: %s can be written by users other than its owner", errUnsafe, d)
		}
		if st.Uid != 0 {
			if owner != 0 && st.Uid != owner {
				return nil, fmt.Errorf("%w: %s belongs to uid %d, inside a directory of uid %d", errUnsafe, d, st.Uid, owner)
			}
			owner = st.Uid
		}
	}
	if owner == 0 {
		// Only root can change anything on the way, so root writes, and gives
		// the new file whatever owner the old one had.
		return nil, nil
	}
	if m, err := metaOf(path); err == nil && m.uid != owner {
		return nil, fmt.Errorf("%w: %s belongs to uid %d, but its directory to uid %d", errUnsafe, path, m.uid, owner)
	}
	return credOfUser(owner)
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

func credOfUser(uid uint32) (*cred, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, fmt.Errorf("looking up uid %d: %w", uid, err)
	}
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	c := &cred{UID: uid, GID: uint32(gid)}
	ids, _ := u.GroupIds()
	for _, s := range ids {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			c.Groups = append(c.Groups, uint32(n))
		}
	}
	return c, nil
}

// acmeDirs are where other ACME clients keep what they manage. A file there
// is rewritten by that client on its own schedule, and the two would overwrite
// each other.
var acmeDirs = []string{"/etc/letsencrypt/", "/etc/dehydrated/", "/var/lib/dehydrated/", "/.acme.sh/", "/var/lib/acme/"}

// pathProblems is what keeps a file from being replaced safely, for discovery
// to warn about before anyone accepts the suggestion.
func pathProblems(path string) []msg {
	var out []msg
	for _, d := range acmeDirs {
		if strings.Contains(path, d) {
			dir := d
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.acme_managed",
					"`{path}` is under `{dir}`, which another ACME client manages, and the two would overwrite each other",
					"path", path, "dir", strings.Trim(dir, "/"))
			})
			break
		}
	}
	if m, err := metaOf(path); err == nil {
		if m.nlink > 1 {
			n := m.nlink
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.hard_link",
					"`{path}` has {links} hard links, and replacing it would leave the other names with the previous content",
					"path", path, "links", n)
			})
		}
		if immutable(path) {
			out = append(out, func(p l10n.Printer) string {
				return p.T("apache.problem.immutable", "`{path}` is immutable or append-only (`chattr +i` or `+a`), so it cannot be replaced", "path", path)
			})
		}
	}
	if _, err := writerFor(path); errors.Is(err, errUnsafe) {
		why := strings.TrimPrefix(err.Error(), errUnsafe.Error()+": ")
		out = append(out, func(p l10n.Printer) string {
			return p.T("apache.problem.unsafe_path",
				"`{path}` cannot be replaced safely, because a user other than its owner could change where its path leads: {reason}",
				"path", path, "reason", why)
		})
	}
	return out
}
