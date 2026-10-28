// Package ops implements the Apache Plugin's three operations, describe,
// discover and deploy; main.go is only the stdio framing. The request and
// response shapes are the shared plugincontract types, so a field added on the
// Agent's side cannot be silently ignored here.
//
// The files, in the order a run uses them: scan.go finds the running masters
// and how each is started, tested and reloaded; config.go reads what httpd
// itself reports about a master's configuration and decides where a client
// reaches each virtual host; discover.go turns that into discovered Targets and
// warnings; write.go replaces a file without changing anything but its
// content; deploy.go and verify.go install a Certificate and check that it is
// served.
package ops

import (
	"runtime/debug"
	"strings"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

const (
	// Name is what this Plugin calls itself and the name the catalog serves it
	// under. It is identity: a Target's settings are stored against it.
	Name = "apache"

	OpDescribe = plugincontract.OpDescribe
	OpDiscover = plugincontract.OpDiscover
	OpDeploy   = plugincontract.OpDeploy
	// OpWriteFile is internal: deploy runs this executable with it under a
	// file owner's credentials. The Agent never sends it.
	OpWriteFile = "write-file"

	// The four settings, keyed by Apache's own directive names so a reader with
	// the configuration open needs no translation. Constants because describe
	// declares them and deploy reads them, and a key is identity: values are
	// stored against it.
	SettingCertificate = "SSLCertificateFile"
	SettingKey         = "SSLCertificateKeyFile"
	SettingTest        = "test"
	SettingReload      = "reload"
)

type (
	SettingDeclaration    = plugincontract.SettingDeclaration
	DescribeResponse      = plugincontract.DescribeResponse
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
// The first two labels are Apache's directive names, which a reader looks for
// in the configuration as written, so they are literals and the same in every
// language. Everything else here is prose and is translated.
func declarations() []SettingDeclaration {
	return []SettingDeclaration{
		{
			Key: SettingCertificate, Label: literal("SSLCertificateFile"), Type: plugincontract.SettingTypePath,
			Required: true, Identity: true, Summary: true,
			Description: T("apache.setting.certificate.description",
				"The file Apache reads the Certificate from, written as the Certificate followed by its chain. "+
					"A discovered Target names the file Apache actually loads, with symlinks followed."),
		},
		{
			Key: SettingKey, Label: literal("SSLCertificateKeyFile"), Type: plugincontract.SettingTypePath,
			Required: true,
			Description: T("apache.setting.key.description",
				"The file Apache reads the private key from.\n\n"+
					"Both files keep everything about the files they replace except their content: owner, mode, "+
					"ACLs and other extended attributes, SELinux label included. A new file is `0600`."),
		},
		{
			Key: SettingTest, Label: T("apache.setting.test.label", "Test command"), Type: plugincontract.SettingTypeCommand,
			Required: true, Default: "apachectl -t",
			Description: T("apache.setting.test.description",
				"Checks the configuration after the files are written and before the reload. "+
					"When it fails, the previous files are put back and nothing is reloaded. "+
					"It runs with the environment and the user of the Apache instance that loads the file, "+
					"and a discovered Target names that instance's own binary and arguments."),
		},
		{
			Key: SettingReload, Label: T("apache.setting.reload.label", "Reload command"), Type: plugincontract.SettingTypeCommand,
			Required: true, Default: "apachectl -k graceful",
			Description: T("apache.setting.reload.description",
				"Makes Apache load the new files. A discovered Target names the command its instance answers to: "+
					"its systemd unit's reload, its OpenRC service's, or a graceful restart of the instance itself."),
		},
	}
}

const plugincontractVersion = plugincontract.ContractVersion
