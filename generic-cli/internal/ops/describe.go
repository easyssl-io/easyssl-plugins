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
// identify an artifact (FR-008a); this is the human-readable label beside them.
const fallbackVersion = "0.1.0"

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

// Describe answers OpDescribe. The declaration is FR-002d's, and it is the
// only place generic-cli's settings are defined: the Client reports this
// verbatim at install time and the Server resolves every value against it, so
// nothing here is repeated Server-side.
func Describe() DescribeResponse {
	return DescribeResponse{
		ContractVersion: ContractVersion,
		Name:            Name,
		Version:         Version(),
		Settings: []SettingDeclaration{{
			Key:   "reload",
			Label: "Reload command",
			Description: "The installation itself. The Client sends this Plugin the Certificate, " +
				"the chain and the key as text; the Plugin writes them to temporary files, names " +
				"them in this script's environment, and deletes them when the script ends. Copying " +
				"what the service reads and reloading it is this script's job.",
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
