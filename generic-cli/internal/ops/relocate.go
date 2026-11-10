package ops

import (
	"errors"
	"fmt"
	"io"
)

// errNothingToRelocate is a relocate with moves, which this Plugin cannot
// carry out: what it said is on stdout.
var errNothingToRelocate = errors.New("generic-cli reads no configuration, so it has nothing to relocate")

// Relocate answers the contract's relocate. This Plugin reads no
// configuration, so it reports no references and no path of its own names a
// file: a request with nothing to move succeeds, changing nothing, and any
// move is refused rather than reported done.
func Relocate(req RelocateRequest, stdout io.Writer) error {
	p := catalog.In(hostLanguage())
	if len(req.Moves) == 0 {
		fmt.Fprintln(stdout, p.T("generic_cli.relocate.nothing", "Nothing to change."))
		return nil
	}
	fmt.Fprintln(stdout, p.T("generic_cli.relocate.refused", "generic-cli reads no configuration, so it has nothing to relocate."))
	return errNothingToRelocate
}
