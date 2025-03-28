package appstore

import (
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

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    as.Iss,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(life)), // Max 20 mins
		Audience:  jwt.ClaimStrings{"appstoreconnect-v1"},
	})
	token.Header["kid"] = as.Kid // Key ID

	keyData, err := os.ReadFile(as.P8)
	if err != nil {
		return fmt.Errorf("createToken: failed to read p8 key: %v", err)
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyData)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	as.token, err = token.SignedString(privateKey)
	if err != nil {
		return fmt.Errorf("signing token: %w", err)
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
