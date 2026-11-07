module github.com/easyssl-io/easyssl-plugins/generic-cli

go 1.26.10

require (
	github.com/easyssl-io/easyssl-contract v0.0.1
	github.com/easyssl-io/easyssl-plugins/internal v0.0.1
)

// Umbrella-dev resolution for the unpublished contract module, the same
// arrangement agent/go.mod uses. The plugin declares what it needs here
// rather than letting a workspace resolve it silently: a workspace that lists
// this module resolves an import it never declared, so the builds and tests
// that count run with GOWORK=off, where only this line reaches the contract.
// Dropped in favor of a version pin once easyssl-contract is published, which
// is also what makes a bare clone of this repository build.
replace github.com/easyssl-io/easyssl-contract => ../../contract

// The code this Plugin shares with the others in this repository, which is a
// module of its own beside them and is never published apart from them.
replace github.com/easyssl-io/easyssl-plugins/internal => ../internal
