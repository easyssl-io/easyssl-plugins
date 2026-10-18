// Command nginx is the easySSL Plugin for nginx: it finds the certificates
// every running nginx master serves, and installs a Certificate at one of them
// by writing the files, testing the configuration and reloading.
//
// An Agent drives it over stdio: the operation name is the single argv
// argument, the JSON request rides stdin, and the answer is the exit status,
// with `discover` also writing a JSON document to stdout.
// Nothing sensitive is ever on argv or in this process's own environment,
// because /proc/<pid>/cmdline is world-readable.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/easyssl-io/easyssl-plugins/nginx/internal/ops"
)

// maxRequest bounds what is read from stdin. A certificate, its chain and a key
// are a few kilobytes, so this is generous while stopping a malformed or
// hostile caller from making the Plugin allocate freely.
const maxRequest = 1 << 20

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		// stderr is this Plugin's own diagnostics, which the Agent logs and
		// never parses; the non-zero exit is what tells it the operation
		// produced no response.
		fmt.Fprintf(os.Stderr, "%s: %v\n", ops.Name, err)
		os.Exit(1)
	}
}

// run is main with its edges passed in, so the stdio framing is testable.
func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s <%s|%s|%s>", ops.Name, ops.OpDescribe, ops.OpDiscover, ops.OpDeploy)
	}
	switch args[0] {
	case ops.OpDescribe:
		return writeJSON(stdout, ops.Describe())
	case ops.OpDiscover:
		return writeJSON(stdout, ops.Discover())
	case ops.OpDeploy:
		var req ops.DeployRequest
		if err := readJSON(stdin, &req); err != nil {
			return fmt.Errorf("reading the deploy request: %w", err)
		}
		// No response document: the exit status is the answer, and everything the run
		// had to say is already on the two streams.
		return ops.Deploy(context.Background(), req, stdout, os.Stderr)
	default:
		// An operation this build does not implement. The Agent treats the
		// non-zero exit here as the operation being unsupported.
		return fmt.Errorf("unknown operation %q", args[0])
	}
}

func readJSON(r io.Reader, v any) error {
	if err := json.NewDecoder(io.LimitReader(r, maxRequest)).Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the request body is empty")
		}
		return err
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}
