package rootcert

import (
	"crypto/x509"
	_ "embed"
	"fmt"
)

// https://www.apple.com/appleca/AppleIncRootCertificate.cer
//
//go:embed data/root.cer
var appleRootCert []byte

var AppleRootCA = NewAppleCert(appleRootCert)

func NewAppleCert(crt []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(crt)
	if err != nil {
		panic(fmt.Errorf("rootcert: could not parse cert: %w", err))
	}
	return cert
}
