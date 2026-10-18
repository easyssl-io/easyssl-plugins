module github.com/easyssl-io/easyssl-plugins/apache

go 1.26.9

require github.com/easyssl-io/easyssl-contract v0.0.1

// Umbrella-dev resolution for the unpublished contract module, the same
// arrangement generic-cli and nginx use; dropped for a version pin once
// easyssl-contract is published.
replace github.com/easyssl-io/easyssl-contract => ../../contract
