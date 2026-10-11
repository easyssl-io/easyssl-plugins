package ops

import (
	_ "embed"
	"runtime/debug"
	"strings"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

// installTemplate is the default value of the one setting this Plugin declares.
// It succeeds while installing nothing: it prints where the material was put
// and returns 0, so a Target created but not yet configured deploys cleanly.
//
//go:embed install.sh.tmpl
var installTemplate string

// fallbackVersion is what this build reports when it carries no module version
// of its own, which is every build made straight from a checkout. The catalog
// and the digest identify an artifact; this is the human-readable label beside
// them. A distribution catalog publishing this checkout must use the same
// value, and both move together.
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

// Discover answers with what this Plugin is and declares. It parses no
// configuration, so it has no installation point to report and nothing to warn
// about, and both lists are empty rather than absent. The declaration below is
// the only place generic-cli's settings are defined: the Agent reports it
// verbatim and the Server resolves every value against it.
func Discover() DiscoverResponse {
	return DiscoverResponse{
		ContractVersion: ContractVersion,
		Name:            Name,
		Version:         Version(),
		Description: T("generic_cli.description", "Installs a Certificate on a host by running a command you write. "+
			"It knows nothing about any particular service: whatever can be done from a "+
			"shell on that host, such as copying files into place, reloading a daemon, or "+
			"calling another tool, this Plugin can do. A service that has a Plugin of its "+
			"own is better served by that one."),
		Settings: []SettingDeclaration{{
			Key: SettingInstall,
			// "Install command", not "Reload command", because reloading is the last
			// thing this script does and not the whole of it: copying the material from
			// the temporary files to where the service reads it is this command's job
			// too.
			Label: T("generic_cli.setting.install.label", "Install command"),
			// The variables are named one per line because they are what the command is
			// written against; the web console renders the newlines. Backticks go around
			// anything a reader would type or look for, and every translation keeps the
			// same spans around the same literals.
			Description: T("generic_cli.setting.install.description", "The command that installs a new Certificate on this Target and reloads "+
				"the service that uses it. Before running it, easySSL writes the material to "+
				"temporary files and passes their paths in the environment, deleting them once the "+
				"command returns. Copying whichever of them the service reads to where it expects "+
				"them, and reloading it, is this command's job.\n\n"+
				"It runs as one `/bin/sh -e` script: a line that fails ends it and fails the "+
				"Deployment, so a failure cannot hide behind a later line that exits 0. Append "+
				"`|| true` to a line that is allowed to fail. A command that must fail the "+
				"Deployment goes on a line of its own: `-e` does not act on a failure on the left "+
				"of `&&` or `||`, or inside a pipeline, so `cp a b && reload; echo done` exits 0 "+
				"when `cp` fails.\n\n"+
				"It runs inside the Agent service's private `/tmp`: a file this command writes "+
				"there is invisible to every other process on the host, and one another process "+
				"put in `/tmp` is invisible here. Hand a file to another daemon somewhere "+
				"else.\n\n"+
				"`EASYSSL_FULLCHAIN_PATH`: the Certificate followed by the issuer chain, which is "+
				"what most servers read.\n"+
				"`EASYSSL_CERT_PATH`: the Certificate alone, without the chain.\n"+
				"`EASYSSL_CHAIN_PATH`: the issuer chain alone, without the Certificate.\n"+
				"`EASYSSL_KEY_PATH`: the private key. It is the only one written 0600, and it exists "+
				"only while the command runs."),
			Type: SettingTypeCommand,
			// Required with a default that runs: this Plugin writes nothing of its own,
			// so a Target with no command installs nothing and must not pretend
			// otherwise. The template default keeps a fresh Target deployable while
			// making plain that it has not been configured yet.
			Default:  installTemplate,
			Required: true,
			Summary:  false,
		}},
		DiscoveredTargets: []DiscoveredTarget{},
		Warnings:          []l10n.Text{},
	}
}
