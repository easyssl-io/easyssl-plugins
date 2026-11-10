module github.com/easyssl-io/easyssl-plugins/apache

go 1.26.10

require (
	github.com/easyssl-io/easyssl-contract v0.1.0
	github.com/easyssl-io/easyssl-plugins/internal v0.0.1
)

// The code this Plugin shares with the others in this repository, which
// is a module of its own beside them and is never published apart from them.
replace github.com/easyssl-io/easyssl-plugins/internal => ../internal

// TODO: drop with the easyssl-contract 0.1.1 release; never merge to main with this replace.
replace github.com/easyssl-io/easyssl-contract => ../../contract
