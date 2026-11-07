module github.com/easyssl-io/easyssl-plugins/apache

go 1.26.10

require (
	github.com/easyssl-io/easyssl-contract v0.0.1
	github.com/easyssl-io/easyssl-plugins/internal v0.0.1
)

// Umbrella-dev resolution for the unpublished contract module, the same
// arrangement generic-cli and nginx use; dropped for a version pin once
// easyssl-contract is published.
replace github.com/easyssl-io/easyssl-contract => ../../contract

// The code this Plugin shares with the others in this repository, which
// is a module of its own beside them and is never published apart from them.
replace github.com/easyssl-io/easyssl-plugins/internal => ../internal
