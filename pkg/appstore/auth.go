package appstore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultJWTLife = time.Minute

func (as *AppStore) createToken(life time.Duration) error {

	if as.token != "" {
		return nil
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"alg": "ES256",
			"kid": as.Kid,
			"typ": "JWT",
		},
		Claims: jwt.MapClaims{
			"iss": as.Iss,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(life).Unix(),
			"aud": "appstoreconnect-v1",
		},
		Method: jwt.SigningMethodES256,
	}

	data, err := os.ReadFile(as.P8)
	if err != nil {
		return fmt.Errorf("createToken: failed to read p8 key: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("createToken: AuthKey must be a valid .p8 PEM file")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("createToken: failed to parse p8 key: %v", err)
	}

	pkey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("createToken: AuthKey must be of type ecdsa.PrivateKey")
	}

	as.token, err = token.SignedString(pkey)
	if err != nil {
		return fmt.Errorf("createToken: failed to sign token: %v", err)
	}

	return nil
}

// GetToken returns the current JWT token
func (as *AppStore) GetToken() string {
	return as.token
}

// GenerateToken generates a new JWT token
func (as *AppStore) GenerateToken(life time.Duration) (string, error) {
	if err := as.createToken(life); err != nil {
		return "", err
	}
	return as.token, nil
}
