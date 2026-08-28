package ops

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

// reloadTemplate is the default value of the one setting this Plugin declares.
// It succeeds while installing nothing: it prints where the material was put
// and returns 0, so a Target created but not yet configured deploys cleanly and
// says what it would have had to work with, instead of failing with an error
// about a command nobody has written yet.
//
//go:embed reload.sh.tmpl
var reloadTemplate string

// fallbackVersion is what this build reports when it carries no module version
// of its own, which is every build made straight from a checkout rather than
// through the module proxy. The catalog and the digest are what actually
// identify an artifact; this is the human-readable label beside them.
const fallbackVersion = "0.0.1"

// Version reports this build's version: the module version stamped into the
// binary when there is one, else fallbackVersion. Read through build info
// rather than an -ldflags variable so a build nobody stamped is still honest
// about being one.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fallbackVersion
	}
	v := strings.TrimPrefix(info.Main.Version, "v")
	// "(devel)" is what the toolchain writes for a build from a working tree.
	if v == "" || v == "(devel)" {
		return fallbackVersion
	}
	return v
}

// Describe answers OpDescribe. This declaration is the only place generic-cli's
// settings are defined: the Agent reports it
// verbatim at install time and the Server resolves every value against it, so
// nothing here is repeated Server-side.
func Describe() DescribeResponse {
	return DescribeResponse{
		ContractVersion: ContractVersion,
		Name:            Name,
		Version:         Version(),
		Description: "Installs a Certificate on a host by running a command you write. " +
			"It knows nothing about any particular service: whatever can be done from a " +
			"shell on that host, such as copying files into place, reloading a daemon, or " +
			"calling another tool, this Plugin can do. A service that has a Plugin of its " +
			"own is better served by that one.",
		Settings: []SettingDeclaration{{
			Key:   "reload",
			Label: "Reload command",
			// The variables are named one per line rather than described as a
			// group: they are what the command is written against, and a
			// reader has to know which file holds what before they can write
			// one. The web console renders the newlines.
			// Written in the Markdown subset the contract allows for a description:
			// backticks around anything a reader would type or look for, so the
			// web console sets it as code rather than running it into the sentence.
			Description: "The command that installs a new Certificate on this Target and reloads " +
				"the service that uses it. Before running it, easySSL writes the material to " +
				"temporary files and passes their paths in the environment, deleting them once the " +
				"command returns. Copying whichever of them the service reads to where it expects " +
				"them, and reloading it, is this command's job.\n\n" +
				"It runs as one `/bin/sh -e` script: a line that fails ends it and fails the " +
				"Deployment, so a failure cannot hide behind a later line that exits 0. Append " +
				"`|| true` to a line that is allowed to fail. A command that must fail the " +
				"Deployment goes on a line of its own: `-e` does not act on a failure on the left " +
				"of `&&` or `||`, or inside a pipeline, so `cp a b && reload; echo done` exits 0 " +
				"when `cp` fails.\n\n" +
				"`EASYSSL_FULLCHAIN_PATH`: the Certificate followed by the issuer chain, which is " +
				"what most servers read.\n" +
				"`EASYSSL_CERT_PATH`: the Certificate alone, without the chain.\n" +
				"`EASYSSL_CHAIN_PATH`: the issuer chain alone, without the Certificate.\n" +
				"`EASYSSL_KEY_PATH`: the private key. It is the only one written 0600, and it exists " +
				"only while the command runs.",
			Type: SettingTypeCommand,
			// Required with a default that runs: the command is the whole of
			// the installation, since this Plugin writes nothing of its own, so
			// a Target with no command installs nothing and must not pretend
			// otherwise. The template default keeps a fresh Target deployable
			// while making plain that it has not been configured yet.
			Default:  reloadTemplate,
			Required: true,
			Summary:  false,
		}},
	}
}
