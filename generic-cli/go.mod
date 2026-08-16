module github.com/easyssl-io/easyssl-plugins/generic-cli

go 1.26.6

require github.com/easyssl-io/easyssl-contract v0.2.0

// Umbrella-dev resolution for the unpublished contract module, the same
// arrangement client/go.mod uses. The plugin declares what it needs here
// rather than letting a workspace resolve it silently, which is why plugins
// stay out of go.work: `GOWORK=off go build` still means something because
// this line is part of the module. Dropped in favor of a version pin once
// easyssl-contract is published, which is also what makes a bare clone of
// this repository build.
replace github.com/easyssl-io/easyssl-contract => ../../contract
