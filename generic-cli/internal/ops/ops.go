// Package ops implements generic-cli's two operations, discover and deploy.
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

	// OpDiscover and OpDeploy are the operation names, each passed as the
	// binary's single argv argument.
	OpDiscover = plugincontract.OpDiscover
	OpDeploy   = plugincontract.OpDeploy

	// SettingTypeCommand is the only setting type this Plugin uses: a shell
	// script run whole via /bin/sh -c, which may span lines.
	SettingTypeCommand = plugincontract.SettingTypeCommand

	// SettingInstall is the key of the one setting this Plugin declares: the
	// script that puts the Certificate where the service reads it and reloads
	// that service.
	//
	// Not "deploy", which is the operation carrying it out and the record it
	// belongs to; a setting read as `Settings["deploy"]` inside the deploy
	// operation of a Deployment gives one word three referents. Not "command"
	// either: `Command` is already the Server's queued instruction to an Agent
	// (wire.Command), and that is a worse collision for being an easySSL noun
	// rather than a common word. "install" is what the script does, in the
	// term the industry uses for putting a certificate onto a service, and it
	// is the only one of the three that names this layer alone.
	//
	// A constant rather than a literal because deploy.go looks it up and
	// discover.go declares it, and a Key is identity: values are stored
	// against it, so the two must never be able to disagree.
	SettingInstall = "install"
)

// The wire shapes, aliased so this package's own signatures read in its terms
// while remaining the very types the Agent decodes into.
type (
	// SettingDeclaration is one setting a Plugin declares about itself.
	SettingDeclaration = plugincontract.SettingDeclaration
	// DiscoverResponse answers OpDiscover.
	DiscoverResponse = plugincontract.DiscoverResponse
	// DiscoveredTarget is one installation point a discovering Plugin
	// reports; this Plugin parses nothing and reports none, and the type is
	// here so Discover can say so with an empty list rather than a nil one.
	DiscoveredTarget = plugincontract.DiscoveredTarget
	// DeployRequest is OpDeploy's request.
	DeployRequest = plugincontract.DeployRequest
)
