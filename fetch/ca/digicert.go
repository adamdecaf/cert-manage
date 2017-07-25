package ca

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/fetch"
)

// Digicert returns a slice of the root certs from their CA
func Digicert() ([]*x509.Certificate, error) {
	cs := fetch.DerCerts{
		Fingerprints: []string{
			"d4de20d05e66fc53fe1a50882c78db2852cae474",
			"5f43e5b1bff8788cac1cc7ca4a9ac6222bcc34c6",
			"0563b8630d62d75abbc8ab1e4bdfb5a899b24d43",
			"a14b48d943ee0a0e40904f3ce0a4c09193515d3f",
			"f517a24f9a48c6c9f8a200269fdc0f482cab3089",
			"df3c24f9bfd666761b268073fe06d1cc8d4f82a4",
			"8e934f88a5a4553336e29b5fb8666048efaa8240",
			"a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436",
			"7e04de896a3e666d00e687d33ffad93be83d349e",
			"5fb7ee0633e259dbad0c4c9ae6d38f1a61c7dc25",
			"3ca0e59c4d40adccc0b9c48cc6335f544e0a0116",
			"ddfb16cd4931c973a2037d3fc83a4d7d775d05e4",
			"97817950d81c9670cc34d809cf794431367ef474",
			"912198eef23dcac40939312fee97dd560bae49b1",
		},
		Urls: []string{
			"https://www.digicert.com/CACerts/BaltimoreCyberTrustRoot.crt",
			"https://www.digicert.com/CACerts/CybertrustGlobalRoot.crt",
			"https://www.digicert.com/CACerts/DigiCertAssuredIDRootCA.crt",
			"https://www.digicert.com/CACerts/DigiCertAssuredIDRootG2.crt",
			"https://www.digicert.com/CACerts/DigiCertAssuredIDRootG3.crt",
			"https://www.digicert.com/CACerts/DigiCertFederatedIDRootCA.crt",
			"https://www.digicert.com/CACerts/DigiCertGlobalRootCA.crt",
			"https://www.digicert.com/CACerts/DigiCertGlobalRootG2.crt",
			"https://www.digicert.com/CACerts/DigiCertGlobalRootG3.crt",
			"https://www.digicert.com/CACerts/DigiCertHighAssuranceEVRootCA.crt",
			"https://www.digicert.com/CACerts/DigiCertPrivateServicesRoot.crt",
			"https://www.digicert.com/CACerts/DigiCertTrustedRootG4.crt",
			"https://www.digicert.com/CACerts/GTECyberTrustGlobalRoot.crt",
			"https://www.digicert.com/CACerts/VerizonGlobalRootCA.crt",
		},
	}
	return cs.Pull()
}
