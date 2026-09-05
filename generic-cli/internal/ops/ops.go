// Package ops implements generic-cli's two operations, describe and install.
// It holds everything the binary does; main.go is only the stdio framing.
//
// The request and response shapes come from the shared plugincontract package
// rather than being redeclared here: the Agent compiles against that same
// definition, so a field added on one side cannot be silently ignored on the
// other. That is worth a dependency, and it costs the plugin nothing it cares
// about, the contract module being first-party and standard library only.
package ops

import "github.com/easyssl-io/easyssl-contract/plugincontract"

// The contract this build speaks, and the identity it answers with. Aliased
// into this package so nothing below has to name plugincontract twice.
const (
	// ContractVersion is the Agent↔Plugin contract version. Additive fields
	// bump MINOR, and a newer MINOR than this one is read by ignoring the
	// fields it does not know.
	ContractVersion = plugincontract.ContractVersion
	// Name is what this Plugin calls itself, and the name the catalog serves
	// it under. It is identity: a Target's settings are stored against it.
	Name = "generic-cli"

	// OpDescribe and OpInstall are the operation names, each passed as the
	// binary's single argv argument.
	OpDescribe = plugincontract.OpDescribe
	OpInstall  = plugincontract.OpInstall

	// SettingTypeCommand is the only setting type this Plugin uses: a shell
	// script run whole via /bin/sh -c, which may span lines.
	SettingTypeCommand = plugincontract.SettingTypeCommand
)

// The wire shapes, aliased so this package's own signatures read in its terms
// while remaining the very types the Agent decodes into.
type (
	// SettingDeclaration is one setting a Plugin declares about itself.
	SettingDeclaration = plugincontract.SettingDeclaration
	// DescribeResponse answers OpDescribe.
	DescribeResponse = plugincontract.DescribeResponse
	// InstallRequest is OpInstall's request.
	InstallRequest = plugincontract.InstallRequest
)
