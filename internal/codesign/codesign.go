package codesign

import (
	"crypto/x509"
	"fmt"
	"os"

	"golang.org/x/crypto/pkcs12"

	"github.com/blacktop/ipsw/internal/codesign/cms"
)

type CMSConfig struct {
	CertChain    []*x509.Certificate
	PrivateKey   any
	Timestamp    bool
	TimestampURL string
	Proxy        string
	Insecure     bool
}

func ParseP12(path, password string) (any, []*x509.Certificate, error) {
	certData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	blocks, err := pkcs12.ToPEM(certData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse pkcs12 file %s: %w", path, err)
	}

	var privateKey any
	var certs []*x509.Certificate

	for _, b := range blocks {
		switch b.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs = append(certs, cert)
		case "PRIVATE KEY":
			if privateKey, err = x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
				outterErr := err
				if privateKey, err = x509.ParseECPrivateKey(b.Bytes); err != nil {
					return nil, nil, fmt.Errorf("failed to parse private key: %w: %w", outterErr, err)
				}
			}
		default:
			return nil, nil, fmt.Errorf("unknown block type: %s", b.Type)
		}
	}

	return privateKey, certs, nil
}

func CreateCMSSignature(data []byte, conf *CMSConfig) ([]byte, error) {
	sd, err := cms.NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Sign(conf.CertChain, conf.PrivateKey); err != nil {
		return nil, err
	}

	if conf.Timestamp {
		if err = sd.AddTimestamps(conf.TimestampURL, conf.Proxy, conf.Insecure); err != nil {
			return nil, fmt.Errorf("failed to add timestamps (RFC3161): %w", err)
		}
	}

	sd.Detached()

	return sd.ToDER()
}
