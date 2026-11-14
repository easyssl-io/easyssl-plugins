module github.com/easyssl-io/easyssl-plugins/apache

go 1.26.11

require (
	github.com/easyssl-io/easyssl-contract v0.2.2
	github.com/easyssl-io/easyssl-plugins/internal v0.0.1
)

// The code this Plugin shares with the others in this repository, which
// is a module of its own beside them and is never published apart from them.
replace github.com/easyssl-io/easyssl-plugins/internal => ../internal

replace github.com/easyssl-io/easyssl-contract => ../../contract
