module github.com/easyssl-io/easyssl-plugins/nginx

go 1.26.6

require (
	github.com/easyssl-io/easyssl-contract v0.0.1
	github.com/nginxinc/nginx-go-crossplane v0.4.89
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/jstemmer/go-junit-report v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

// Umbrella-dev resolution for the unpublished contract module, the same
// arrangement generic-cli uses; dropped for a version pin once
// easyssl-contract is published.
replace github.com/easyssl-io/easyssl-contract => ../../contract
