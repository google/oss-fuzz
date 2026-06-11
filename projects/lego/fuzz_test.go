package lego_test

import (
	"testing"
	"github.com/go-acme/lego/v5/certcrypto"
)

func FuzzParsePEMBundle(f *testing.F) {
	seeds := []string{
		"-----BEGIN CERTIFICATE-----\nMIIBtzCCARwCCQDA\n-----END CERTIFICATE-----\n",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"",
	}
	for _, s := range seeds { f.Add(s) }
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			certcrypto.ParsePEMBundle([]byte(data))
		}()
	})
}

func FuzzParsePEMPrivateKey(f *testing.F) {
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAAJBAN\n-----END RSA PRIVATE KEY-----\n")
	f.Add("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			certcrypto.ParsePEMPrivateKey([]byte(data))
		}()
	})
}

func FuzzPEMDecodeToX509CSR(f *testing.F) {
	f.Add("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			certcrypto.PemDecodeTox509CSR([]byte(data))
		}()
	})
}

func FuzzParsePEMCertificate(f *testing.F) {
	f.Add("-----BEGIN CERTIFICATE-----\nMIIBtzCCARwCCQDA\n-----END CERTIFICATE-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			certcrypto.ParsePEMCertificate([]byte(data))
		}()
	})
}

func FuzzPEMDecode(f *testing.F) {
	f.Add("-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n")
	f.Add("not-pem-data")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			certcrypto.PEMDecode([]byte(data))
			certcrypto.PemDecodeTox509CSR([]byte(data))
		}()
	})
}
