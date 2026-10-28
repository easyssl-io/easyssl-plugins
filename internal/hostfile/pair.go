package hostfile

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/easyssl-io/easyssl-plugins/internal/pemfile"
)

// Written is what WritePair replaced, for putting it back.
type Written struct {
	op    string
	files []previous
}

// previous is one replaced file: nil data when there was none.
type previous struct {
	path string
	data []byte
}

// WritePair writes a certificate file and a key file, each as the user its
// directory belongs to (WriteAs, with op), then reads both back and checks
// they belong together, so a file changed between the two writes is caught
// before a reload loads it. It refuses to replace an encrypted key, whose
// protection the new one would not keep, before writing anything. Any later
// failure puts back what it had already written.
func WritePair(op, certPath, keyPath string, cert, key []byte, stdout, stderr io.Writer) (*Written, error) {
	w := &Written{op: op}
	if old, err := ReadSafely(keyPath); err != nil {
		return nil, fmt.Errorf("reading the current %s: %w", keyPath, err)
	} else if old != nil && pemfile.EncryptedKey(old) {
		return nil, fmt.Errorf("the current %s is encrypted, and the new key would not keep that protection, so nothing was written", keyPath)
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{certPath, cert}, {keyPath, key}} {
		old, err := ReadSafely(f.path)
		if err != nil {
			w.Restore(stdout, stderr)
			return nil, fmt.Errorf("reading the current %s: %w", f.path, err)
		}
		if f.path == keyPath && old != nil && pemfile.EncryptedKey(old) {
			w.Restore(stdout, stderr) // encrypted since the check above
			return nil, fmt.Errorf("the current %s is encrypted, and the new key would not keep that protection", keyPath)
		}
		if err := WriteAs(op, f.path, f.data, false); err != nil {
			w.Restore(stdout, stderr)
			return nil, fmt.Errorf("writing %s: %w", f.path, err)
		}
		w.files = append(w.files, previous{f.path, old})
		fmt.Fprintf(stdout, "wrote %s (%s)\n", f.path, Describe(f.path, old != nil))
	}
	cb, err1 := ReadSafely(certPath)
	kb, err2 := ReadSafely(keyPath)
	if err := errors.Join(err1, err2); err != nil {
		w.Restore(stdout, stderr)
		return nil, err
	}
	if err := pemfile.PairMatches(cb, kb); err != nil {
		w.Restore(stdout, stderr)
		return nil, fmt.Errorf("the files read back do not belong together (%v), so something else changed them; the previous files were put back", err)
	}
	return w, nil
}

// Restore puts back what WritePair replaced, last written first, or removes a
// file that did not exist before. Best effort and reported: the run is
// already failing, and what it could not undo is what the operator needs to
// read.
func (w *Written) Restore(stdout, stderr io.Writer) {
	if w == nil {
		return
	}
	for i := len(w.files) - 1; i >= 0; i-- {
		p := w.files[i]
		err := WriteAs(w.op, p.path, p.data, p.data == nil)
		switch {
		case err != nil && !errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stderr, "could not put back %s: %v\n", p.path, err)
		case p.data == nil:
			fmt.Fprintf(stdout, "removed %s, which did not exist before\n", p.path)
		default:
			fmt.Fprintf(stdout, "put back the previous %s\n", p.path)
		}
	}
	w.files = nil
}
