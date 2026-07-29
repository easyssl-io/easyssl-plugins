// Command generic-cli is the general-purpose easySSL plugin: it writes the
// certificate material at the paths it is given and runs the reload command it
// is given. It parses no server configuration and knows nothing about any
// particular server software.
//
// It builds to a standalone executable that a Client fetches, verifies against
// a published digest, and then drives over stdio.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "generic-cli: not implemented yet")
	os.Exit(1)
}
