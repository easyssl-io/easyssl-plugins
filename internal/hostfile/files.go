package hostfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"
)

// Change is a file's new content and the content it was read with, so a file
// edited by someone else in between is refused rather than overwritten.
type Change struct {
	Path     string
	Old, New []byte
}

// WriteAll replaces each file with its new content, as the user its directory
// belongs to (WriteAs, with op), keeping everything about it but its content.
// Before writing a file it checks that the file still holds Old; any failure
// puts back what it had already written. What it returns puts every file back
// (Revert), with its modification time: a server that compares its
// configuration's times with when it last loaded it would otherwise take a
// file put back as one edited since.
func WriteAll(op string, changes []Change) (*Written, error) {
	w := &Written{op: op}
	for _, c := range changes {
		cur, err := ReadSafely(c.Path)
		if err == nil && cur == nil {
			err = os.ErrNotExist
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("reading %s: %w", c.Path, err), w.Revert())
		}
		if !bytes.Equal(cur, c.Old) {
			return nil, errors.Join(fmt.Errorf("%s changed since it was read", c.Path), w.Revert())
		}
		var mtime time.Time
		if fi, err := os.Lstat(c.Path); err == nil {
			mtime = fi.ModTime()
		}
		if err := WriteAs(op, c.Path, c.New, false); err != nil {
			return nil, errors.Join(fmt.Errorf("writing %s: %w", c.Path, err), w.Revert())
		}
		w.files = append(w.files, previous{path: c.Path, data: c.Old, mtime: mtime})
	}
	return w, nil
}

// Revert puts back every file WriteAll or WritePair replaced, last written
// first, or removes one that did not exist before, and says which it could
// not. Restore is the same for a Deployment's output.
func (w *Written) Revert() error {
	if w == nil {
		return nil
	}
	var errs []error
	for i := len(w.files) - 1; i >= 0; i-- {
		p := w.files[i]
		if err := WriteAs(w.op, p.path, p.data, p.data == nil); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("putting back %s: %w", p.path, err))
			continue
		}
		// Only in a directory root alone can change: os.Chtimes follows a
		// symlink, which in a user's directory that user could plant.
		if wr, err := WriterFor(p.path); err == nil && (wr == nil || wr.UID == uint32(os.Geteuid())) && !p.mtime.IsZero() {
			if err := os.Chtimes(p.path, time.Time{}, p.mtime); err != nil {
				errs = append(errs, fmt.Errorf("putting back the modification time of %s: %w", p.path, err))
			}
		}
	}
	w.files = nil
	return errors.Join(errs...)
}
