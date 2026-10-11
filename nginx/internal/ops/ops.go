// Package ops implements the nginx Plugin's two operations, discover and
// deploy; main.go is only the stdio framing. The request and response shapes
// are the shared plugincontract types, so a field added on the Agent's side
// cannot be silently ignored here.
package ops

import (
	"runtime/debug"
	"strings"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

const (
	// Name is what this Plugin calls itself and the name the catalog serves it
	// under. It is identity: a Target's settings are stored against it.
	Name = "nginx"

	OpDiscover = plugincontract.OpDiscover
	OpDeploy   = plugincontract.OpDeploy

	// The four settings, keyed by nginx's own directive names so a reader
	// with nginx.conf open needs no translation. Constants because discover
	// declares them and deploy reads them, and a key is identity: values are
	// stored against it.
	SettingCertificate = "ssl_certificate"
	SettingKey         = "ssl_certificate_key"
	SettingTest        = "test"
	SettingReload      = "reload"
)

type (
	SettingDeclaration    = plugincontract.SettingDeclaration
	DiscoverResponse      = plugincontract.DiscoverResponse
	DiscoveredTarget      = plugincontract.DiscoveredTarget
	DiscoveredCertificate = plugincontract.DiscoveredCertificate
	ExtraDatum            = plugincontract.ExtraDatum
	DeployRequest         = plugincontract.DeployRequest
)

// fallbackVersion is what a build with no module version of its own reports,
// which is every build made from a checkout. The distribution catalog serving
// this checkout uses the same value, and both move together.
const fallbackVersion = "0.0.1"

// Version reports the module version stamped into the binary, else
// fallbackVersion.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fallbackVersion
	}
	v := strings.TrimPrefix(info.Main.Version, "v")
	if v == "" || v == "(devel)" {
		return fallbackVersion
	}
	return v
}

// declarations is the only place this Plugin's settings are defined: the
// Agent reports them verbatim and the Server resolves every value against
// them.
//
// The first two labels are nginx's directive names, which a reader looks for
// in nginx.conf as written, so they are literals and the same in every
// language. Everything else here is prose and is translated.
func declarations() []SettingDeclaration {
	return []SettingDeclaration{
		{
			Key: SettingCertificate, Label: literal("ssl_certificate"), Type: plugincontract.SettingTypePath,
			Required: true, Identity: true, Summary: true,
			Description: T("nginx.setting.ssl_certificate.description",
				"The file nginx reads the Certificate from, written as the Certificate followed by its chain. "+
					"A discovered Target names the file nginx actually loads, with symlinks followed."),
		},
		{
			Key: SettingKey, Label: literal("ssl_certificate_key"), Type: plugincontract.SettingTypePath,
			Required: true,
			Description: T("nginx.setting.ssl_certificate_key.description",
				"The file nginx reads the private key from.\n\n"+
					"Both files keep the permissions, owner and SELinux label of the files they replace; a new file is `0600`."),
		},
		{
			Key: SettingTest, Label: T("nginx.setting.test.label", "Test command"), Type: plugincontract.SettingTypeCommand,
			Required: true, Default: "nginx -t",
			Description: T("nginx.setting.test.description",
				"Checks the configuration after the files are written and before the reload. "+
					"When it fails, the previous files are put back and nothing is reloaded. "+
					"A discovered Target names the instance's own binary and configuration."),
		},
		{
			Key: SettingReload, Label: T("nginx.setting.reload.label", "Reload command"), Type: plugincontract.SettingTypeCommand,
			Required: true, Default: "nginx -s reload",
			Description: T("nginx.setting.reload.description",
				"Makes nginx load the new files. A discovered Target names the command its instance answers to: "+
					"its systemd unit's reload, its OpenRC service's, or the signal."),
		},
	}
}

const plugincontractVersion = plugincontract.ContractVersion
