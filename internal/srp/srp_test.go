package srp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestDerivePassword(t *testing.T) {
	password := []byte("synthetic-password")
	salt := []byte("synthetic-salt")
	digest := sha256.Sum256(password)

	s2k, err := derivePassword(ProtocolS2K, password, salt, 1000)
	if err != nil {
		t.Fatalf("s2k: %v", err)
	}
	if want := pbkdf2.Key(digest[:], salt, 1000, 32, sha256.New); !bytes.Equal(s2k, want) {
		t.Errorf("s2k derived key mismatch")
	}

	s2kfo, err := derivePassword(ProtocolS2KFO, password, salt, 1000)
	if err != nil {
		t.Fatalf("s2k_fo: %v", err)
	}
	hexDigest := []byte(hex.EncodeToString(digest[:]))
	if want := pbkdf2.Key(hexDigest, salt, 1000, 32, sha256.New); !bytes.Equal(s2kfo, want) {
		t.Errorf("s2k_fo derived key mismatch")
	}
	if bytes.Equal(s2k, s2kfo) {
		t.Errorf("s2k and s2k_fo must derive different keys")
	}

	if _, err := derivePassword(PasswordProtocol("bogus"), password, salt, 1000); err == nil {
		t.Errorf("expected error for unsupported protocol")
	}
}
