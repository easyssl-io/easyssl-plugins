// Package ops implements generic-cli's two operations, describe and install.
// It holds everything the binary does; main.go is only the stdio framing.
//
// The request and response shapes are declared here rather than imported. This
// module is deliberately dependency-free: it must build from a bare clone of
// its own repository, so it cannot require the contract module while that one
// is unpublished, and Principle V's audit story is worth more than sharing a
// struct. The field names and the ContractVersion below are the contract, and
// they must move together with it; the Client's copy lives in the
// plugincontract package.
package ops

// ContractVersion is the Client↔Plugin contract this build speaks. Additive
// fields bump MINOR, and a newer MINOR than this one is read by ignoring the
// fields it does not know.
const ContractVersion = "1.0.0"

// Name is what this Plugin calls itself, and the name the catalog serves it
// under. It is identity: a Target's settings are stored against it.
const Name = "generic-cli"

// Operation names, each passed as the binary's single argv argument.
const (
	OpDescribe = "describe"
	OpInstall  = "install"
)

// SettingTypeCommand is the only setting type this Plugin uses: a shell script
// run whole via /bin/sh -c, which may span lines.
const SettingTypeCommand = "command"

// SettingDeclaration is one setting this Plugin declares about itself. Key is
// identity, so it is never renamed between versions; Label and Description may
// change freely, nothing being stored against them.
type SettingDeclaration struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Summary     bool   `json:"summary"`
}

// DescribeResponse answers OpDescribe: who this build is and what it declares.
type DescribeResponse struct {
	ContractVersion string               `json:"contractVersion"`
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	Settings        []SettingDeclaration `json:"settings"`
}

// InstallRequest is OpInstall's request. The material arrives as PEM text
// rather than as paths, so a Plugin installing through an API needs no file;
// this one does need files and creates them inside WorkDir.
type InstallRequest struct {
	ContractVersion string `json:"contractVersion"`
	CertificatePem  string `json:"certificatePem"`
	ChainPem        string `json:"chainPem"`
	PrivateKeyPem   string `json:"privateKeyPem"`
	// WorkDir is a directory the Client created for this run and removes after
	// it, however it ends: a run the Client had to kill cannot leave key
	// material behind.
	WorkDir string `json:"workDir"`
	// Settings is the Server-resolved value of every setting declared above.
	// The Plugin trusts it and resolves nothing itself.
	Settings map[string]string `json:"settings"`
}

// InstallResponse answers OpInstall. OK is the deployment's outcome; Output is
// one text, whatever this Plugin chooses to say, with the inner command's exit
// status described inside it rather than carried as a field.
type InstallResponse struct {
	ContractVersion string `json:"contractVersion"`
	OK              bool   `json:"ok"`
	Output          string `json:"output"`
}
