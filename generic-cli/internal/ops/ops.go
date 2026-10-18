// Package ops implements generic-cli's three operations, describe, discover
// and deploy; main.go is only the stdio framing. The request and response
// shapes are the shared plugincontract types the Agent compiles against, so a
// field added on one side cannot be silently ignored on the other.
package ops

import "github.com/easyssl-io/easyssl-contract/plugincontract"

const (
	ContractVersion = plugincontract.ContractVersion
	// Name is what this Plugin calls itself, and the name the catalog serves
	// it under. It is identity: a Target's settings are stored against it.
	Name = "generic-cli"

	OpDescribe = plugincontract.OpDescribe
	OpDiscover = plugincontract.OpDiscover
	OpDeploy   = plugincontract.OpDeploy

	// SettingTypeCommand is the only setting type this Plugin uses.
	SettingTypeCommand = plugincontract.SettingTypeCommand

	// SettingInstall is the key of the one setting this Plugin declares: the
	// script that puts the Certificate where the service reads it and reloads that
	// service. Not "deploy", which is the operation and the record it belongs to,
	// and not "command", which is the Server's queued instruction to an Agent
	// (wire.Command).
	//
	// A constant because deploy.go looks it up and describe declares it, and
	// values are stored against a Key, so the two must never disagree.
	SettingInstall = "install"
)

// The wire shapes, aliased so this package's own signatures read in its terms
// while remaining the very types the Agent decodes into.
type (
	SettingDeclaration = plugincontract.SettingDeclaration
	// DescribeResponse answers OpDescribe.
	DescribeResponse = plugincontract.DescribeResponse
	// DiscoverResponse answers OpDiscover.
	DiscoverResponse = plugincontract.DiscoverResponse
	// DiscoveredTarget is here so Discover can report an empty list rather than a
	// nil one; this Plugin parses nothing and reports none.
	DiscoveredTarget = plugincontract.DiscoveredTarget
	// DeployRequest is OpDeploy's request.
	DeployRequest = plugincontract.DeployRequest
)
