package ops

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// As many installation points as one answer reports, each with a leaf and a
// chain, still make an answer an installed Agent reads: it refuses one past
// 256 KiB.
func TestAFullAnswerWithPEMStaysReadable(t *testing.T) {
	pemBlock := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat(strings.Repeat("A", 64)+"\n", 17) + "-----END CERTIFICATE-----\n"
	targets := make([]DiscoveredTarget, plugincontract.MaxDiscoveredTargets)
	for i := range targets {
		path := fmt.Sprintf("/etc/nginx/ssl/site-%03d.example.com/fullchain.pem", i)
		targets[i] = DiscoveredTarget{
			Settings: map[string]string{
				SettingCertificate: path, SettingKey: strings.Replace(path, "fullchain", "privkey", 1),
				"test": "/usr/sbin/nginx -t", "reload": "systemctl reload nginx.service",
			},
			ExtraData: []ExtraDatum{},
			References: []plugincontract.Reference{
				{Setting: SettingCertificate, File: "/etc/nginx/sites-enabled/site.conf", Line: 11, Value: path},
			},
			Warnings: []l10n.Text{},
			Certificate: &DiscoveredCertificate{
				Domains: []string{"site.example.com", "www.site.example.com"}, KeyType: "ec_p256",
				SHA256: strings.Repeat("a", 64), CertificatePem: pemBlock, ChainPem: pemBlock,
			},
		}
	}
	budgetPEM(targets)
	raw, err := json.Marshal(plugincontract.DiscoverResponse{ContractVersion: plugincontract.ContractVersion, DiscoveredTargets: targets, Warnings: []l10n.Text{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 256<<10 {
		t.Fatalf("a full answer is %d bytes, past the 262144 an Agent reads", len(raw))
	}
	if targets[0].Certificate.CertificatePem == "" {
		t.Error("the first certificates lost their leaf too")
	}
}
